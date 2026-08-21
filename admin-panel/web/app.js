// Bazarish project (c) 2026
// The operator panel. Everything past the sign-in page is drawn here from the
// panel's JSON API; the panel itself holds no user state, it passes the calls
// through to the service that owns the accounts.
(function () {
    "use strict";

    // How often the monitoring view re-probes the fleet.
    var kHealthPollMs = 5000;
    // How long to wait after the last keystroke before searching, so a typed
    // fingerprint is one request rather than fifty-two.
    var kSearchDebounceMs = 250;
    var kBytesPerMiB = 1024 * 1024;
    // A quota an operator can enter, in whole megabytes.
    var kMinQuotaMiB = 1;
    var kMaxQuotaMiB = 1024 * 1024;

    var content = document.getElementById("content");
    var nav = document.getElementById("nav");
    var pollTimer = null;

    function api(method, path, body) {
        return fetch(path, {
            method: method,
            headers: body ? { "Content-Type": "application/json" } : {},
            body: body ? JSON.stringify(body) : undefined,
            credentials: "same-origin"
        }).then(function (response) {
            if (response.status === 401) {
                window.location.href = "/login";
                throw new Error("signed out");
            }
            return response.json().catch(function () {
                throw new Error("HTTP " + response.status);
            }).then(function (data) {
                if (!response.ok) {
                    throw new Error(data.error || ("HTTP " + response.status));
                }
                return data;
            });
        });
    }

    function element(tag, className, text) {
        var node = document.createElement(tag);
        if (className) {
            node.className = className;
        }
        if (text !== undefined) {
            node.textContent = text;
        }
        return node;
    }

    function fact(label, value) {
        var row = element("li");
        row.appendChild(element("span", null, label));
        row.appendChild(element("b", null, value));
        return row;
    }

    function humanBytes(bytes) {
        var units = ["B", "KiB", "MiB", "GiB", "TiB"];
        var value = Number(bytes) || 0;
        var unit = 0;
        while (value >= 1024 && unit + 1 < units.length) {
            value /= 1024;
            unit += 1;
        }
        return (value < 10 ? value.toFixed(1) : Math.round(value)) + " " + units[unit];
    }

    function humanDate(unixSeconds) {
        if (!unixSeconds) {
            return "never";
        }
        return new Date(unixSeconds * 1000).toISOString().replace("T", " ").slice(0, 16);
    }

    function notice(message, kind) {
        var box = element("p", "notice" + (kind ? " " + kind : ""), message);
        return box;
    }

    // --- monitoring -------------------------------------------------------

    function serviceCard(service) {
        var card = element("div", "card");
        var head = element("div", "card-head");
        head.appendChild(element("i", "dot " + (service.up ? "is-up" : "is-down")));
        head.appendChild(element("span", "card-name", service.name));
        head.appendChild(element("span", "tag", service.up ? "up" : "down"));
        card.appendChild(head);

        var facts = element("ul", "facts");
        facts.appendChild(fact("kind", service.kind));
        facts.appendChild(fact("address", service.url));
        if (service.up) {
            facts.appendChild(fact("version", service.version || "-"));
            facts.appendChild(fact("uptime", service.uptime));
            facts.appendChild(fact("memory",
                humanBytes(service.ramBytes) + " / " + humanBytes(service.ramPeakBytes) + " peak"));
        } else {
            facts.appendChild(fact("error",
                (service.error || "no answer") + (service.status ? " (HTTP " + service.status + ")" : "")));
        }
        facts.appendChild(fact("latency", service.latencyMs + " ms"));
        card.appendChild(facts);
        return card;
    }

    function renderMonitoring() {
        content.innerHTML = "";
        content.appendChild(element("h1", "view-title", "monitoring"));
        var cards = element("div", "cards");
        content.appendChild(cards);

        function load() {
            api("GET", "/api/services").then(function (data) {
                cards.innerHTML = "";
                if (!data.services.length) {
                    cards.appendChild(element("p", "muted", "No services configured."));
                }
                data.services.forEach(function (service) {
                    cards.appendChild(serviceCard(service));
                });
            }).catch(function (error) {
                cards.innerHTML = "";
                cards.appendChild(notice(error.message, "is-error"));
            });
        }

        load();
        pollTimer = window.setInterval(load, kHealthPollMs);
    }

    // --- users ------------------------------------------------------------

    function approvalTag(user) {
        if (user.approval === "pending") {
            return element("span", "tag is-pending", "pending");
        }
        if (user.approval === "approved") {
            return element("span", "tag is-approved", "approved");
        }
        return element("span", "tag", "no account");
    }

    function userDetail(user, onChanged) {
        var box = element("div", "detail");
        box.appendChild(element("p", "detail-key", user.user));

        var facts = element("ul", "facts");
        facts.appendChild(fact("approval", user.approval));
        facts.appendChild(fact("registered", humanDate(user.requestedAt)));
        if (user.approval === "approved") {
            facts.appendChild(fact("approved", humanDate(user.approvedAt)));
        }
        facts.appendChild(fact("subscription",
            user.subscribed ? "until " + humanDate(user.notAfter) : "not redeemed yet"));
        facts.appendChild(fact("delegation",
            user.transientExpires ? "until " + humanDate(user.transientExpires) : "none"));
        box.appendChild(facts);

        var label = element("p", "field-label", "Storage quota");
        box.appendChild(label);
        var row = element("div", "quota-row");
        var input = element("input", "field");
        input.type = "number";
        input.min = String(kMinQuotaMiB);
        input.max = String(kMaxQuotaMiB);
        input.step = "1";
        input.value = String(Math.max(kMinQuotaMiB, Math.round(user.quotaBytes / kBytesPerMiB)));
        row.appendChild(input);
        row.appendChild(element("span", "quota-unit", "MB"));
        var save = element("button", "btn btn-quiet", "Save quota");
        row.appendChild(save);
        box.appendChild(row);

        var actions = element("div", "actions");
        if (user.approval === "pending") {
            var approve = element("button", "btn", "Approve account");
            approve.addEventListener("click", function () {
                approve.disabled = true;
                api("POST", "/api/approve", { user: user.user }).then(function () {
                    onChanged("Approved. The account is served from now on.");
                }).catch(function (error) {
                    approve.disabled = false;
                    box.appendChild(notice(error.message, "is-error"));
                });
            });
            actions.appendChild(approve);
        }
        box.appendChild(actions);

        save.addEventListener("click", function () {
            var megabytes = Number(input.value);
            if (!Number.isFinite(megabytes) || megabytes < kMinQuotaMiB || megabytes > kMaxQuotaMiB) {
                box.appendChild(notice("A quota is a whole number of megabytes.", "is-error"));
                return;
            }
            save.disabled = true;
            api("PUT", "/api/quota", {
                user: user.user,
                quotaBytes: Math.round(megabytes) * kBytesPerMiB
            }).then(function () {
                onChanged("Quota set to " + Math.round(megabytes) + " MB.");
            }).catch(function (error) {
                save.disabled = false;
                box.appendChild(notice(error.message, "is-error"));
            });
        });

        return box;
    }

    function renderUsers(selected) {
        content.innerHTML = "";
        content.appendChild(element("h1", "view-title", "users"));

        var state = "all";
        // The open account is in the address bar, so an operator can hand a
        // colleague a link to the account they are talking about.
        var openUser = selected || null;
        var flash = null;

        var toolbar = element("div", "toolbar");
        var search = element("input", "field search");
        search.type = "search";
        search.placeholder = "Search by fingerprint";
        search.autocomplete = "off";
        toolbar.appendChild(search);

        var chips = {};
        ["all", "pending", "approved"].forEach(function (name) {
            var chip = element("button", "chip" + (name === state ? " is-on" : ""), name);
            chip.addEventListener("click", function () {
                state = name;
                Object.keys(chips).forEach(function (key) {
                    chips[key].className = "chip" + (key === state ? " is-on" : "");
                });
                load();
            });
            chips[name] = chip;
            toolbar.appendChild(chip);
        });
        content.appendChild(toolbar);

        var count = element("p", "muted", "");
        content.appendChild(count);
        var rows = element("div", "rows");
        content.appendChild(rows);

        function load() {
            var query = "/api/users?q=" + encodeURIComponent(search.value.trim())
                + "&state=" + encodeURIComponent(state);
            api("GET", query).then(function (data) {
                rows.innerHTML = "";
                count.textContent = data.total === data.users.length
                    ? data.total + " account(s)"
                    : "showing " + data.users.length + " of " + data.total;
                if (flash) {
                    rows.parentNode.insertBefore(flash, rows);
                }
                if (!data.users.length) {
                    rows.appendChild(element("p", "muted", "Nothing here."));
                    return;
                }
                data.users.forEach(function (user) {
                    var row = element("button", "row" + (openUser === user.user ? " is-open" : ""));
                    row.type = "button";
                    row.appendChild(element("span", "row-key", user.user));
                    row.appendChild(approvalTag(user));
                    row.appendChild(element("span", "row-quota",
                        Math.round(user.quotaBytes / kBytesPerMiB) + " MB"));
                    row.addEventListener("click", function () {
                        openUser = openUser === user.user ? null : user.user;
                        flash = null;
                        setHash(openUser ? "#/users/" + openUser : "#/users");
                        load();
                    });
                    rows.appendChild(row);
                    if (openUser === user.user) {
                        rows.appendChild(userDetail(user, function (message) {
                            flash = notice(message);
                            load();
                        }));
                    }
                });
            }).catch(function (error) {
                rows.innerHTML = "";
                rows.appendChild(notice(error.message, "is-error"));
            });
        }

        var debounce = null;
        search.addEventListener("input", function () {
            window.clearTimeout(debounce);
            debounce = window.setTimeout(load, kSearchDebounceMs);
        });
        load();
        search.focus();
    }

    // --- routing ----------------------------------------------------------

    var views = { monitoring: renderMonitoring, users: renderUsers };

    function route() {
        window.clearInterval(pollTimer);
        pollTimer = null;
        var parts = (window.location.hash || "#/monitoring").replace("#/", "").split("/");
        var name = views[parts[0]] ? parts[0] : "monitoring";
        Array.prototype.forEach.call(nav.querySelectorAll("a"), function (link) {
            link.className = link.dataset.view === name ? "is-current" : "";
        });
        views[name](parts[1]);
    }

    // A hash the page writes itself must not redraw the page: the list already
    // shows what the new address describes, and a redraw would throw away the
    // search that led there.
    var ownHashWrite = false;

    function setHash(value) {
        if (window.location.hash === value) {
            return;
        }
        ownHashWrite = true;
        window.location.hash = value;
    }

    window.addEventListener("hashchange", function () {
        if (ownHashWrite) {
            ownHashWrite = false;
            return;
        }
        route();
    });
    route();
})();
