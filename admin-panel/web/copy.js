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

    function copyIcon(source, title) {
        var button = document.createElement("button");
        button.type = "button";
        button.className = "icon-copy";
        button.title = title || "Copy";
        button.setAttribute("aria-label", button.title);
        button.innerHTML = "<svg viewBox=\"0 0 16 16\" aria-hidden=\"true\">"
            + "<rect x=\"5.5\" y=\"5.5\" width=\"8\" height=\"9\" rx=\"1.5\"/>"
            + "<path d=\"M10.5 3.5 H3.5 A1.5 1.5 0 0 0 2 5 v7\"/></svg>";
        button.addEventListener("click", function (event) {
            event.stopPropagation();
            copy(source()).then(function () {
                button.classList.add("is-done");
            }, function () {
                button.classList.add("is-failed");
            }).then(function () {
                window.setTimeout(function () {
                    button.classList.remove("is-done");
                    button.classList.remove("is-failed");
                }, kFeedbackMs);
            });
        });
        return button;
    }

    window.bazarishCopy = { copy: copy, button: copyButton, icon: copyIcon };

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
