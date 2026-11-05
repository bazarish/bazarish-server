// Bazarish project (c) 2026
"use strict";

const kLanguages = [
    ["en", "English"],
    ["ru", "Русский"],
    ["es", "Español"],
    ["zh", "中文"],
    ["ar", "العربية"],
];
const kRightToLeft = ["ar"];
const kLanguageKey = "bazarish-admin-language";

function knownLanguage(code) {
    return kLanguages.some(([known]) => known === code);
}

function chosenLanguage() {
    try {
        const kept = localStorage.getItem(kLanguageKey);
        if (kept && knownLanguage(kept)) {
            return kept;
        }
    } catch (error) {
        return "en";
    }
    const asked = (navigator.language || "en").slice(0, 2);
    return knownLanguage(asked) ? asked : "en";
}

let language = chosenLanguage();

function N_(text) {
    return text;
}

function t(text, ...values) {
    const table = language === "en" ? null : (window.bazarishMessages || {})[language];
    let out = table && table[text] ? table[text] : text;
    values.forEach((value, index) => {
        out = out.split("%" + (index + 1)).join(String(value));
    });
    return out;
}

function applyLanguage() {
    document.documentElement.lang = language;
    document.documentElement.dir = kRightToLeft.includes(language) ? "rtl" : "ltr";
    for (const marked of document.querySelectorAll("[data-t]")) {
        marked.textContent = t(marked.dataset.t);
    }
}

function setLanguage(code) {
    language = code;
    applyLanguage();
    try {
        localStorage.setItem(kLanguageKey, code);
    } catch (error) {
        return;
    }
}

function languagePicker(changed) {
    const box = document.createElement("details");
    box.className = "lang";
    const now = document.createElement("summary");
    now.className = "lang-now";
    now.setAttribute("aria-label", t("Language"));
    now.textContent = kLanguages.find(([code]) => code === language)[1];
    const list = document.createElement("ul");
    list.className = "lang-list";
    for (const [code, name] of kLanguages) {
        const item = document.createElement("li");
        const choice = document.createElement("button");
        choice.type = "button";
        choice.className = "lang-one" + (code === language ? " is-on" : "");
        choice.lang = code;
        choice.textContent = name;
        choice.onclick = () => {
            box.open = false;
            setLanguage(code);
            now.textContent = name;
            now.setAttribute("aria-label", t("Language"));
            for (const other of list.querySelectorAll(".lang-one")) {
                other.classList.toggle("is-on", other === choice);
            }
            changed();
        };
        item.append(choice);
        list.append(item);
    }
    box.append(now, list);
    return box;
}

applyLanguage();
