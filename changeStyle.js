function toggleStyleSheet(){
    // 1 (a) Get style element by ID (hint: getElementById)
    var element = document.getElementById("switch-style");

    // 1 (b) Check the current stylesheet file name. (hint: element.getAttribute)
    // 1 (c) Determine new stylesheet file name
    // 1 (d) replace stylesheet with new stylesheet (hint: element.setAttribute)

    var filename = (element.getAttribute("href") == "style1.css") ? "style2.css" : "style1.css"; 
    element.setAttribute("href", filename);
    localStorage.setItem("currStyle", filename);
}


window.onload = function(){
    
    // 2 (a) get stylesheet name from local storage hint: localStorage.getItem(name)
    var sheetName = localStorage.getItem("currStyle");
    
    if (sheetName === null) {
        sheetName = "style1.css";
    }
 
    // 2 (b) get html style element by ID
    var element = document.getElementById("switch-style");

    // 2 (c) replace href attribute of html element.
    element.setAttribute("href", sheetName);
}

