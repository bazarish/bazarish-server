// Bazarish project (c) 2026
(function () {
    "use strict";

    var kSignInPollMs = 2000;

    function watchSignIn(block) {
        var timer = window.setInterval(function () {
            window.fetch(block.dataset.signWait, {credentials: "same-origin"})
                .then(function (answer) {
                    return answer.ok ? answer.json() : null;
                })
                .then(function (state) {
                    if (!state || state.state === "waiting") {
                        return;
                    }
                    window.clearInterval(timer);
                    if (state.state === "signedIn") {
                        window.location.assign("/");
                        return;
                    }
                    block.querySelector("[data-sign-expired]").hidden = false;
                }, function () {
                });
        }, kSignInPollMs);
    }

    function offerSignInTabs() {
        var bar = document.querySelector("[data-signin-tabs]");
        if (!bar) {
            return;
        }
        var panes = document.querySelectorAll("[data-signin-pane]");
        var tabs = bar.querySelectorAll("[data-signin-show]");
        var show = function (name) {
            for (var p = 0; p < panes.length; ++p) {
                panes[p].hidden = panes[p].dataset.signinPane !== name;
            }
            for (var t = 0; t < tabs.length; ++t) {
                tabs[t].classList.toggle("is-on", tabs[t].dataset.signinShow === name);
            }
        };
        bar.hidden = false;
        bar.addEventListener("click", function (event) {
            if (event.target.dataset && event.target.dataset.signinShow) {
                show(event.target.dataset.signinShow);
            }
        });
        show("copy");
    }

    document.addEventListener("DOMContentLoaded", function () {
        document.getElementById("languageSlot").appendChild(languagePicker(function () {}));
        offerSignInTabs();
        var waiting = document.querySelector("[data-sign-wait]");
        if (waiting) {
            watchSignIn(waiting);
        }
        var blob = document.getElementById("blob");
        if (!blob) {
            return;
        }

        document.addEventListener("click", function (event) {
            if (event.target.classList.contains("btn-copy")) {
                blob.focus();
            }
        });

        blob.addEventListener("keydown", function (event) {
            if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
                blob.form.requestSubmit();
            }
        });

        blob.addEventListener("paste", function () {
            window.setTimeout(function () {
                blob.value = blob.value.trim();
            }, 0);
        });
    });
})();
