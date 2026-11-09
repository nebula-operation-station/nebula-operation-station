// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Boot script of the attack-path overlay renderer document (ADR 0011 D10,
// VU-24), loaded as <script type="module"> under the frame's strict CSP. It
// starts the traffic map in the element with id "trafficmap" with the
// overlay read from its data-paths attribute. The traffic model still
// arrives from the parent page through the bridge.

import { startTrafficMap } from "./main.js";
import { readPaths, REJECTED } from "./paths.js";

const root = document.getElementById("trafficmap");
// This document always carries an overlay; a missing one is a rejection,
// never a silently normal map.
if (root) startTrafficMap(root, { paths: readPaths(root) || REJECTED });
