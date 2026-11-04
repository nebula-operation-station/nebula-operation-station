// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Boot script for the renderer page (loaded as <script type="module">
// under the strict CSP). It starts the map in the element with id
// "trafficmap"; the page itself is added by TM19.

import { startTrafficMap } from "./main.js";

const root = document.getElementById("trafficmap");
if (root) startTrafficMap(root);
