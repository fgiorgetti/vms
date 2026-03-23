/*
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
*/

"use strict";

//
// This module is responsible for setting up the requested ingresses into a Skupper v2 site.
//
// The input to this module is a set of ConfigMaps that represent configured access points:
//   metadata.annotations:
//     skx/state-type: accesspoint
//     skx/state-id:   <The database ID of the source BackboneAccessPoint>
//   data:
//     kind: [claim|peer|member|manage]
//
// The output of this module:
//   Skupper v2 RouterAccess resources
//   Ingress bundles for the API
//

import {
    GetRouterAccesses,
    GetNetworkAccesses,
    DeleteRouterAccess,
    DeleteNetworkAccess,
    Annotation,
    Controlled,
    ApplyObject,
    GetConfigmaps,
    WatchConfigMaps,
    startWatchRouterAccesses
} from '@skupperx/modules/kube';
import { Log } from '@skupperx/modules/log'
import {
    ROUTER_SERVICE_NAME,
    META_ANNOTATION_SKUPPERX_CONTROLLED,
    APPLICATION_ROUTER_LABEL,
    META_ANNOTATION_STATE_ID,
    META_ANNOTATION_STATE_TYPE,
    STATE_TYPE_ACCESS_POINT
} from '@skupperx/modules/common'
import { UpdateLocalState } from './sync-site-kube.js';
import { createHash } from 'node:crypto';
import { setTimeout } from 'node:timers/promises';
import { log } from 'node:console';

let reconcile_config_map_scheduled      = false;
let reconcile_accesses_scheduled = false;
let accessPoints = {}; // APID => {kind, routerPort, syncHash, syncData, toDelete}

const new_access_point = function(apid, kind) {
    let value = {
        kind       : kind,
        routerPort : null,
        syncHash   : null,
        syncData   : {},
        toDelete   : false,
    };

    if (accessPoints[apid]) {
        throw Error(`accessPoint already exists for ${apid}`);
    }
    accessPoints[apid] = value;
}

const free_access_point = function(apid) {
    const ap = accessPoints[apid];
    if (ap) {
        delete accessPoints[apid];
    }
}

const backbone_ingress = function(apid) {
    const access = accessPoints[apid];
    switch (access.kind) {
        case 'manage':
            return backbone_routeraccess(apid);
        case 'van':
            return backbone_networkaccess(apid);
        default:
            throw new Error(`Unknown access kind: ${access.kind}`);
    }
}

const backbone_routeraccess = function(apid) {
    const access = accessPoints[apid];
    const name   = `skx-${access.kind}-${apid}`;
    let routerAccess = {
        apiVersion : 'skupper.io/v2alpha1',
        kind       : 'RouterAccess',
        metadata : {
            name : name,
            annotations : {
                [META_ANNOTATION_SKUPPERX_CONTROLLED] : 'true',
                [META_ANNOTATION_STATE_ID]            : apid,
            },
        },
        spec: {
            tlsCredentials: name,
            generateTlsCredentials: true,
            roles : [{
                name: getRouterAccessRole(access.kind)
            }],
        },
    };
    return routerAccess;
}

const backbone_networkaccess = function(apid) {
    const access = accessPoints[apid];
    const name   = `skx-${access.kind}-${apid}`;
    networkAccess = {
        apiVersion : 'skupper.io/v2alpha1',
        kind       : 'NetworkAccess',
        metadata : {
            name : name,
            annotations : {
                [META_ANNOTATION_SKUPPERX_CONTROLLED] : 'true',
                [META_ANNOTATION_STATE_ID]            : apid,
            },
        },
        spec: {
            tlsCredentials: name,
            generateTlsCredentials: true,
        },
    };
    return networkAccess;
}

function getRouterAccessRole(kind) {
    switch (kind) {
        case "van":
            return "inter-network";
        case "manage":
            return "normal";
        case "peer":
            return "inter-router";
        case "member":
            return "edge";
        default:
            throw new Error(`Unknown kind: ${kind}`);
    }
}

function getEndpointKind(role) {
    switch (role) {
        case "inter-network":
            return "van";
        case "normal":
            return "manage";
        case "inter-router":
            return "peer";
        case "edge":
            return "member";
        default:
            throw new Error(`Unknown role: ${role}`);
    }
}

const do_reconcile_accesses = async function() {
    try {
        await reconcile_accesses();
    } catch (err) {
        console.log("Error reconciling accesses:", err);
    } finally {
        //
        // Allow router accesses and network accesses to be reconciled again
        //
        reconcile_accesses_scheduled = false;
    }
}

const reconcile_accesses = async function() {
    let endpoints = {
        "van": {},
        "manage": {},
        "peer": {},
        "member": {},
    };

    // Retrieving NetworkAccesses ("van" accesspoints)
    for (const networkAccess of await GetNetworkAccesses()) {
        const apid = Annotation(networkAccess, META_ANNOTATION_STATE_ID);
        if (!Controlled(networkAccess)) {
            continue;
        }
        for (const endpoint of networkAccess.status.endpoints) {
            if (endpoint.name == "inter-network") {
                endpoints["van"][apid] = {
                    host: endpoint.host,
                    port: endpoint.port,
                    group: endpoint.group,
                    kind: "NetworkAccess",
                    name: networkAccess.name,
                    delete: true,
                };
            }
        }
    }

    // Retrieving RouterAccesses ("manage", "peer" and "member" accesspoints)
    for (const routerAccess of await GetRouterAccesses()) {
        const apid = Annotation(routerAccess, META_ANNOTATION_STATE_ID);
        if (!Controlled(routerAccess)) {
            continue;
        }
        for (const endpoint of routerAccess.status.endpoints) {
            let endpointKind = getEndpointKind(endpoint.name);
            // ensure no HA related endpoint is used
            if (endpoint.group == "skupper-router") {
                endpoints[endpointKind][apid] = {
                    host: endpoint.host,
                    port: endpoint.port,
                    group: endpoint.group,
                    kind: "RouterAccess",
                    name: routerAccess.metadata.name,
                    delete: true,
                };
            }
        }
    }

    // TODO: remove (debug purposes only)
    for (const kind in endpoints) {
        for (const apid in endpoints[kind]) {
            const endpoint = endpoints[kind][apid];
            console.log(`endpoint ${endpoint.name} for ${kind} is ${endpoint.host}:${endpoint.port}`);
        }
    }

    for (const [apid, ap] of Object.entries(accessPoints)) {
        if (ap.kind in endpoints && apid in endpoints[ap.kind]) {
            const endpoint = endpoints[ap.kind][apid];
            let hash = null;
            let data = {};
            data = {
                host : endpoint.host,
                port : endpoint.port,
            };
            hash = ingressHash(data);
            if (hash != ap.syncHash) {
                accessPoints[apid].syncHash = hash;
                accessPoints[apid].syncData = data;
                await UpdateLocalState(`accessstatus-${apid}`, hash, data);
            }
            endpoint.delete = false;
        } else {
            await ApplyObject(backbone_ingress(apid));
        }
    }

    //
    // Any remaining endpoints (NetworkAccess or RouterAccess) with delete = true were not found in the accessPoints. Delete them.
    //
    for (const kind in endpoints) {
        for (const apid in endpoints[kind]) {
            const endpoint = endpoints[kind][apid];
            if (endpoint.delete === true) {
                switch(endpoint.kind) {
                    case 'NetworkAccess':
                        await DeleteNetworkAccess(endpoint.name);
                        break;
                    case 'RouterAccess':
                        await DeleteRouterAccess(endpoint.name);
                        break;
                }
            }
        }
    }
}

const reconcile_router_accesses = async function() {
    if (!reconcile_accesses_scheduled) {
        reconcile_accesses_scheduled = true;
        await setTimeout(200);
        await do_reconcile_accesses();
    }
}

const ingressHash = function(data) {
    if (data == {}) {
        return null;
    }

    let text = 'host' + data.host + 'port' + data.port;
    return createHash('sha1').update(text).digest('hex');
}

export function GetIngressBundle() {
    let bundle = {};

    for (const [apid, ap] of Object.entries(accessPoints)) {
        if (ap.syncHash) {
            bundle[apid] = {
                host : ap.syncData.host,
                port : ap.syncData.port,
            };
        }
    }

    return bundle;
}

export async function GetInitialState() {
    await do_reconcile_config_maps();
    await do_reconcile_accesses();
    return GetIngressBundle();
}

const do_reconcile_config_maps = async function() {
    reconcile_config_map_scheduled = false;
    const all_config_maps = await GetConfigmaps();
    let ingress_config_maps = {};
    let need_service_sync   = false;

    //
    // Build a map of all configured access points from the config maps.
    //
    for (const cm of all_config_maps) {
        if (Controlled(cm) && Annotation(cm, META_ANNOTATION_STATE_TYPE) == STATE_TYPE_ACCESS_POINT) {
            const apid = Annotation(cm, META_ANNOTATION_STATE_ID);
            if (apid) {
                ingress_config_maps[apid] = cm;
            }
        }
    }

    //
    // Mark all local access points as candidates for deletion.
    //
    for (const apid of Object.keys(accessPoints)) {
        accessPoints[apid].toDelete = true;
    }

    //
    // Un-condemn still-existing ingresses and create new ones.
    //
    for (const [apid, cm] of Object.entries(ingress_config_maps)) {
        if (Object.keys(accessPoints).indexOf(apid) >= 0) {
            accessPoints[apid].toDelete = false;
        } else {
            const kind = cm.data.kind;
            new_access_point(apid, kind);
            need_service_sync = true;
        }
    }

    //
    // Delete access points that are no longer mentioned in the config maps.
    //
    for (const [apid, ap] of Object.entries(accessPoints)) {
        if (ap.toDelete) {
            free_access_point(apid);
            need_service_sync = true;
        }
    }

    //
    // If the list of ingresses has been altered in any way, re-sync the ingress service.
    //
    if (need_service_sync) {
        await reconcile_router_accesses();
    }
}

const reconcile_config_maps = async function() {
    if (!reconcile_config_map_scheduled) {
        reconcile_config_map_scheduled = true;
        await setTimeout(200);
        await do_reconcile_config_maps();
    }
}

const onConfigMapWatch = function(type, apiObj) {
    try {
        const controlled = Controlled(apiObj);
        const state_type = Annotation(apiObj, META_ANNOTATION_STATE_TYPE);
        if (controlled && state_type == STATE_TYPE_ACCESS_POINT) {
            reconcile_config_maps();
        }
    } catch (e) {
        Log('Exception caught in ingress.onConfigMapWatch');
        Log(e.stack);
    }
}

const onRouterAccessWatch = async function(type, route) {
    console.log(`onRouterAccessWatch: ${type} event for RouterAccess ${route.metadata.name}`);
    if (Controlled(route)) {
        await reconcile_router_accesses();
    }
}

export function GetIngressBundleV2() {
    let bundle = {};
    for (const [apid, ap] of Object.entries(accessPoints)) {
        if (ap.syncHash) {
            bundle[apid] = {
                host : ap.syncData.host,
                port : ap.syncData.port,
            };
        }
    }

    return bundle;
}

export async function Start(siteId) {
    Log('[Ingress Skupper v2 module started]');
    await do_reconcile_config_maps();
    await do_reconcile_accesses();
    WatchConfigMaps(onConfigMapWatch);
    startWatchRouterAccesses(onRouterAccessWatch);
}
