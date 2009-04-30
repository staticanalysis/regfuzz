var imp = 3; /* 0 == jscript, 1 == spidermonkey, 2 == dom, 3 == acroread */

// if (imp == 3) console.show();

function log(msg) {
    switch (imp) {
        case 0: WScript.echo(msg); break;
        case 1: print(msg); break;
        case 2: document.write("<p>" + msg + "</p>"); break;
        case 3: console.println(msg); break;
    }
}


while (true) {
  var regex = app.response("Enter regex (q to quit):")
  if (regex == "q")
    break;
  var flags = app.response("Enter flags:")
  try {
      var r = new RegExp(regex, flags);
      if (r.test(regex)) {
        log("matched for /" + regex + "/" + flags);
      } else {
        log("no match for /" + regex + "/" + flags);
      }
  } catch (e) {
    log("error for /" + regex + "/" + flags);
    app.alert(e);
  }
}
