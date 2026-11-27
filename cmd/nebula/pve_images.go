// SPDX-License-Identifier: AGPL-3.0-or-later

// Local PVE image entries (ADR 0008 amendment 2, D3 (a), PV-03d).
//
// `nebula pve image add|remove|list` only call the executor RPCs
// AddPVELocalImage, RemovePVELocalImage (role admin only) and
// ListPVEImages over the peer-credential-authenticated admin socket. The
// CLI writes no file: the executor is the only writer of the local
// entries, checks the caller's role, validates the entry with the image
// catalog grammar (the "local-" prefix included), persists and audits it.
// The CLI only bounds its arguments and shows the executor's answer.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	grpcstatus "google.golang.org/grpc/status"

	"github.com/nebula-operation-station/nebula-operation-station/internal/release"
	pb "github.com/nebula-operation-station/nebula-operation-station/internal/rpc/executorv1"
)

// Argument bounds of `nebula pve image`. They only keep oversized input
// off the socket; the executor enforces the catalog grammar.
const (
	// maxPveImageIDArg bounds the image ID (the catalog grammar allows 64
	// bytes).
	maxPveImageIDArg = 64
	// maxPveImageOSArg and maxPveImageReleaseArg bound --os and --release
	// (32 bytes in the catalog grammar).
	maxPveImageOSArg      = 32
	maxPveImageReleaseArg = 32
	// maxPveImageArchArg and maxPveImageFormatArg bound --arch (amd64,
	// arm64) and --disk-format (qcow2, raw).
	maxPveImageArchArg   = 16
	maxPveImageFormatArg = 16
	// maxPveImageURLArg bounds --url like the catalog grammar.
	maxPveImageURLArg = release.MaxImageURL
	// pveImageSHA256Len is the length of a hex SHA-256.
	pveImageSHA256Len = 64
)

// pveImageArgOK reports whether s is non-empty valid UTF-8 of at most
// limit bytes.
func pveImageArgOK(s string, limit int) bool {
	return s != "" && len(s) <= limit && utf8.ValidString(s)
}

// pveImageRPCError renders an executor refusal (role, prefix, validation,
// store) as text: the status code and the executor's fixed message.
func pveImageRPCError(what, id string, err error) error {
	st := grpcstatus.Convert(err)
	if id != "" {
		what += " " + safe(id)
	}
	return fmt.Errorf("%s refused by the executor (%s): %s", what, st.Code(), safe(st.Message()))
}

func pveImageCmd(args []string, stdin io.Reader, w io.Writer) error {
	if len(args) == 0 {
		return errors.New(strings.TrimSpace(pveUsage))
	}
	switch args[0] {
	case "add":
		return pveImageAdd(args[1:], stdin, w)
	case "remove":
		return pveImageRemove(args[1:], stdin, w)
	case "list":
		return pveImageList(args[1:], w)
	}
	return errors.New(strings.TrimSpace(pveUsage))
}

// pveImageAdd implements `nebula pve image add`.
func pveImageAdd(args []string, stdin io.Reader, w io.Writer) error {
	fs := flag.NewFlagSet("pve image add", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	osName := fs.String("os", "", "distribution, e.g. rocky")
	rel := fs.String("release", "", "release, e.g. 9.4")
	arch := fs.String("arch", "", "amd64 or arm64")
	url := fs.String("url", "", "https URL of the vendor cloud image")
	sum := fs.String("sha256", "", "lowercase hex SHA-256 of the image file")
	format := fs.String("disk-format", "", "qcow2 or raw")
	id, flagArgs := pveSplitID(args)
	if err := fs.Parse(flagArgs); err != nil {
		return fmt.Errorf("%w\n%s", err, strings.TrimSpace(pveUsage))
	}
	if fs.NArg() != 0 || !pveImageArgOK(id, maxPveImageIDArg) {
		return errors.New(strings.TrimSpace(pveUsage))
	}
	for _, a := range []struct {
		name, v string
		limit   int
	}{
		{"--os", *osName, maxPveImageOSArg},
		{"--release", *rel, maxPveImageReleaseArg},
		{"--arch", *arch, maxPveImageArchArg},
		{"--url", *url, maxPveImageURLArg},
		{"--sha256", *sum, pveImageSHA256Len},
		{"--disk-format", *format, maxPveImageFormatArg},
	} {
		if !pveImageArgOK(a.v, a.limit) {
			return fmt.Errorf("%s is required: valid UTF-8, at most %d bytes\n%s", a.name, a.limit, strings.TrimSpace(pveUsage))
		}
	}
	img := &pb.PVECatalogImage{Id: id, Os: *osName, Release: *rel, Arch: *arch, Url: *url, Sha256: *sum, DiskFormat: *format}

	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewExecutorServiceClient(conn)
	fmt.Fprintln(w, "local image entry (trust local; compare the SHA-256 with the vendor's out of band):")
	pveShowImage(w, img)
	line, err := pveAskLine(stdin, fmt.Sprintf("Type 'yes' to add local image %s (an existing local entry with this id is replaced): ", safe(id)), "confirmation")
	if err != nil {
		return err
	}
	if line != "yes" {
		return errors.New("not added")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := c.AddPVELocalImage(ctx, &pb.AddPVELocalImageRequest{Image: img}); err != nil {
		return pveImageRPCError("add local image", id, err)
	}
	fmt.Fprintf(w, "local image %s stored by the executor\n", safe(id))
	return nil
}

// pveShowImage prints one entry for review.
func pveShowImage(w io.Writer, img *pb.PVECatalogImage) {
	fmt.Fprintf(w, "  id:          %s\n", safe(img.GetId()))
	fmt.Fprintf(w, "  os/release:  %s %s\n", safe(img.GetOs()), safe(img.GetRelease()))
	fmt.Fprintf(w, "  arch:        %s\n", safe(img.GetArch()))
	fmt.Fprintf(w, "  url:         %s\n", safe(img.GetUrl()))
	fmt.Fprintf(w, "  sha256:      %s\n", safe(img.GetSha256()))
	fmt.Fprintf(w, "  disk format: %s\n", safe(img.GetDiskFormat()))
}

// pveImageRemove implements `nebula pve image remove`.
func pveImageRemove(args []string, stdin io.Reader, w io.Writer) error {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") || !pveImageArgOK(args[0], maxPveImageIDArg) {
		return errors.New(strings.TrimSpace(pveUsage))
	}
	id := args[0]
	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewExecutorServiceClient(conn)
	line, err := pveAskLine(stdin, fmt.Sprintf("Type 'yes' to remove local image %s (a template prepared from it no longer binds): ", safe(id)), "confirmation")
	if err != nil {
		return err
	}
	if line != "yes" {
		return errors.New("not removed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.RemovePVELocalImage(ctx, &pb.RemovePVELocalImageRequest{ImageId: id})
	if err != nil {
		return pveImageRPCError("remove local image", id, err)
	}
	if !res.GetRemoved() {
		return fmt.Errorf("no local image %s; nothing changed", safe(id))
	}
	fmt.Fprintf(w, "local image %s removed by the executor\n", safe(id))
	return nil
}

// pveImageList implements `nebula pve image list`: the signed and local
// catalog entries and the prepared template records. Read only.
func pveImageList(args []string, w io.Writer) error {
	if len(args) != 0 {
		return errors.New(strings.TrimSpace(pveUsage))
	}
	conn, err := dialExecutor()
	if err != nil {
		return err
	}
	defer conn.Close()
	c := pb.NewExecutorServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := c.ListPVEImages(ctx, &pb.ListPVEImagesRequest{})
	if err != nil {
		return pveImageRPCError("list pve images", "", err)
	}
	if res.GetCatalogDigest() == "" {
		fmt.Fprintln(w, "no signed catalog loaded")
	} else {
		fmt.Fprintf(w, "signed catalog: sequence %d, digest %s\n", res.GetCatalogSequence(), safe(res.GetCatalogDigest()))
	}
	if len(res.GetImages()) == 0 {
		fmt.Fprintln(w, "no pve images")
	} else {
		tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tTRUST\tOS\tRELEASE\tARCH\tFORMAT\tSHA256\tURL")
		for _, e := range res.GetImages() {
			img := e.GetImage()
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", safe(img.GetId()), safe(e.GetTrust()), safe(img.GetOs()),
				safe(img.GetRelease()), safe(img.GetArch()), safe(img.GetDiskFormat()), safe(img.GetSha256()), safe(img.GetUrl()))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(res.GetTemplates()) == 0 {
		fmt.Fprintln(w, "no prepared templates")
		return nil
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "REMOTE\tNODE\tSTORAGE\tIMAGE\tTRUST\tVMID\tGEN\tSOURCE SHA256\tPREPARED")
	for _, r := range res.GetTemplates() {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%s\t%s\n", safe(r.GetRemoteId()), safe(r.GetNode()), safe(r.GetStorage()),
			safe(r.GetImageId()), safe(r.GetTrust()), r.GetVmid(), r.GetGeneration(), safe(r.GetSourceSha256()),
			time.Unix(r.GetPreparedAtUnix(), 0).UTC().Format(time.RFC3339))
	}
	return tw.Flush()
}
