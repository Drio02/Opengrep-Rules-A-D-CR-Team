function showLog(log, xhr, data) {
  // ok: jsfe-xss-innerhtml
  log.innerHTML = "";
  // ok: jsfe-xss-innerhtml
  log.innerHTML = "Proof of Work failed, try again";
  // ruleid: jsfe-xss-innerhtml
  log.innerHTML = "Generation failed:\n" + data;
  // ruleid: jsfe-xss-innerhtml
  log.innerHTML = xhr.responseText;
  // ruleid: jsfe-xss-innerhtml
  document.write(location.hash);
}
