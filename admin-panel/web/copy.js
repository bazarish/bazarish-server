// Bazarish project (c) 2026
// Copy-to-clipboard, shared by the sign-in page and the app. Loaded on its own by
// the sign-in page, which otherwise needs no scripts at all: without this the
// page still works, it just asks the operator to select the text themselves.
(function () {
    "use strict";

    // How long a button says what it did before going back to its name.
    var kFeedbackMs = 1600;

    function copy(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }
        // Plain HTTP has no clipboard API, so fall back to a selection the old
        // command can take.
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

    // A button that copies what `source` returns and says so afterwards. A copy
    // that fails says that too: a button that silently does nothing is worse than
    // no button.
    function copyButton(label, source, className) {
        var button = document.createElement("button");
        button.type = "button";
        button.className = className || "btn btn-quiet btn-copy";
        button.textContent = label;
        button.addEventListener("click", function () {
            copy(source()).then(function () {
                button.textContent = "Copied";
            }, function () {
                button.textContent = "Select it and copy";
            }).then(function () {
                window.setTimeout(function () {
                    button.textContent = label;
                }, kFeedbackMs);
            });
        });
        return button;
    }

    window.bazarishCopy = { copy: copy, button: copyButton };

    // Every block meant to be taken away gets a button of its own.
    document.addEventListener("DOMContentLoaded", function () {
        var blocks = document.querySelectorAll("pre.copy");
        for (var i = 0; i < blocks.length; ++i) {
            (function (block) {
                block.parentNode.insertBefore(copyButton("Copy", function () {
                    return block.textContent;
                }), block.nextSibling);
            })(blocks[i]);
        }
    });
})();
