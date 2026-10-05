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
        var button = document.createElement("button");
        button.type = "button";
        button.className = "btn btn-quiet btn-copy";
        button.textContent = "Copy";
        button.addEventListener("click", function () {
            copy(block.textContent).then(function () {
                button.textContent = "Copied";
            }, function () {
                button.textContent = "Select it and copy";
            }).then(function () {
                window.setTimeout(function () {
                    button.textContent = "Copy";
                }, kFeedbackMs);
            });
        });
        block.parentNode.insertBefore(button, block.nextSibling);
    }

    var blocks = document.querySelectorAll("pre.copy");
    for (var i = 0; i < blocks.length; ++i) {
        addButton(blocks[i]);
    }
})();
