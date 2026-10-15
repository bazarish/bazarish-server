// Bazarish project (c) 2026
(function () {
    "use strict";

    var kFeedbackMs = 1600;

    function copy(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }
        var area = document.createElement("textarea");
        area.value = text;
        area.setAttribute("readonly", "");
        area.style.position = "fixed";
        area.style.opacity = "0";
        document.body.appendChild(area);
        area.select();
        var copied = document.execCommand("copy");
        document.body.removeChild(area);
        return copied ? Promise.resolve() : Promise.reject(new Error("the browser refused"));
    }

    function addButton(block) {
        var words = document.body.dataset;
        var button = document.createElement("button");
        button.type = "button";
        button.className = "btn btn-quiet btn-copy";
        button.textContent = words.copyDo;
        button.addEventListener("click", function () {
            copy(block.textContent).then(function () {
                button.textContent = words.copyDone;
            }, function () {
                button.textContent = words.copyByhand;
            }).then(function () {
                window.setTimeout(function () {
                    button.textContent = words.copyDo;
                }, kFeedbackMs);
            });
        });
        var after = block.closest(".copy-row") || block;
        after.parentNode.insertBefore(button, after.nextSibling);
    }

    var blocks = document.querySelectorAll("pre.copy");
    for (var i = 0; i < blocks.length; ++i) {
        addButton(blocks[i]);
    }

    function addPopup(opener) {
        var popup = document.getElementById(opener.hash.slice(1));
        if (!popup) {
            return;
        }
        function close() {
            popup.classList.remove("is-open");
            document.removeEventListener("keydown", onKey);
        }
        function onKey(event) {
            if (event.key === "Escape") {
                close();
            }
        }
        opener.addEventListener("click", function (event) {
            event.preventDefault();
            popup.classList.add("is-open");
            document.addEventListener("keydown", onKey);
        });
        popup.addEventListener("click", function (event) {
            event.preventDefault();
            close();
        });
    }

    var openers = document.querySelectorAll("a.btn-qr");
    for (var j = 0; j < openers.length; ++j) {
        addPopup(openers[j]);
    }
})();
