// SPDX-License-Identifier: AGPL-3.0-or-later

package reputation

import "slices"

// FeedID names a reputation feed. The IDs are a fixed list on the NOS side
// (ADR 0011 D5 source IDs, ADR 0012 D6); a feed cannot choose its own ID.
type FeedID string

// The five keyless feeds of ADR 0012 Q3. No feed here needs an API key.
const (
	// FeedFeodo is the abuse.ch Feodo Tracker IP blocklist.
	FeedFeodo FeedID = "feodo"
	// FeedSSLBL is the abuse.ch SSL Blacklist IP list.
	FeedSSLBL FeedID = "sslbl"
	// FeedSpamhausDROP is the Spamhaus DROP netblock list.
	FeedSpamhausDROP FeedID = "spamhaus-drop"
	// FeedSpamhausEDROP is the Spamhaus EDROP netblock list.
	FeedSpamhausEDROP FeedID = "spamhaus-edrop"
	// FeedFireHOLLevel1 is the FireHOL level1 aggregate list.
	FeedFireHOLLevel1 FeedID = "firehol-level1"
)

// Category is the reason a feed lists an entry. Every category is fixed by
// the feed that yields it.
type Category string

// The categories of ADR 0012 D6.
const (
	// CategoryBotnetC2 marks botnet command-and-control addresses.
	CategoryBotnetC2 Category = "botnet-c2"
	// CategoryHijackedNetblock marks hijacked or criminal netblocks.
	CategoryHijackedNetblock Category = "hijacked-netblock"
	// CategoryAggregate marks entries of an aggregate list.
	CategoryAggregate Category = "aggregate"
)

// feedCategories is the fixed feed-to-category mapping of ADR 0012 D6.
var feedCategories = map[FeedID]Category{
	FeedFeodo:         CategoryBotnetC2,
	FeedSSLBL:         CategoryBotnetC2,
	FeedSpamhausDROP:  CategoryHijackedNetblock,
	FeedSpamhausEDROP: CategoryHijackedNetblock,
	FeedFireHOLLevel1: CategoryAggregate,
}

// Category returns the fixed category of the feed. It reports false for an
// ID that is not in the fixed list.
func (f FeedID) Category() (Category, bool) {
	c, ok := feedCategories[f]
	return c, ok
}

// Feeds returns the registered feed IDs in sorted order.
func Feeds() []FeedID {
	ids := make([]FeedID, 0, len(feedCategories))
	for id := range feedCategories {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}
