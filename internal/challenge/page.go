package challenge

// challengePageHTML is the challenge page served to gray-listed IPs.
// It uses a JavaScript proof-of-work that runs in the browser.
// Template args: %s=IP, %s=nonce, %s=token, %d=difficulty, %d=difficulty
const challengePageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Check</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:system-ui,-apple-system,sans-serif;min-height:100vh;display:flex;justify-content:center;align-items:center;background:#1a2234;color:#c8d3e0}
.card{background:#243049;border-radius:12px;padding:48px;max-width:480px;width:90%%;text-align:center;box-shadow:0 8px 32px rgba(0,0,0,.3)}
h1{font-size:1.5em;margin-bottom:8px;color:#fff}
.subtitle{color:#8899aa;margin-bottom:32px;font-size:.9em}
.shield{font-size:64px;margin-bottom:16px;display:block}
.progress-wrap{background:#1a2234;border-radius:8px;height:8px;margin:24px 0;overflow:hidden}
.progress-bar{height:100%%;background:linear-gradient(90deg,#206bc4,#4299e1);width:0%%;transition:width .3s;border-radius:8px}
.status{color:#8899aa;font-size:.85em;min-height:1.4em}
.status.done{color:#2fb344}
.status.fail{color:#d63939}
.ip{font-family:monospace;color:#6c7a89;font-size:.8em;margin-top:16px}
noscript .warn{background:#d63939;color:#fff;padding:16px;border-radius:8px;margin-top:16px}
</style>
</head>
<body>
<div class="card">
  <span class="shield">&#128737;</span>
  <h1>Checking your connection</h1>
  <p class="subtitle">This is an automated security check. Please wait.</p>
  <div class="progress-wrap"><div class="progress-bar" id="bar"></div></div>
  <p class="status" id="status">Verifying...</p>
  <noscript><div class="warn">JavaScript is required to complete this security check.</div></noscript>
  <p class="ip">Your IP: %s</p>
</div>
<script>
(function(){
  var nonce = "%s";
  var token = "%s";
  var difficulty = %d;
  var prefix = "";
  for(var i=0;i<difficulty;i++) prefix+="0";

  var bar = document.getElementById("bar");
  var status = document.getElementById("status");
  var counter = 0;
  var batchSize = 50000;

  function sha256(msg){
    var buf = new TextEncoder().encode(msg);
    return crypto.subtle.digest("SHA-256",buf).then(function(h){
      return Array.from(new Uint8Array(h)).map(function(b){return b.toString(16).padStart(2,"0")}).join("");
    });
  }

  function solve(){
    var promises = [];
    for(var i=0;i<batchSize;i++){
      promises.push(sha256(nonce+counter.toString(16)));
      counter++;
    }
    Promise.all(promises).then(function(hashes){
      for(var i=0;i<hashes.length;i++){
        if(hashes[i].substring(0,%d)===prefix){
          var solution = (counter-batchSize+i).toString(16);
          status.textContent = "Verified!";
          status.className = "status done";
          bar.style.width = "100%%";
          // Submit
          var form = document.createElement("form");
          form.method = "POST";
          form.action = "/challenge/verify";
          var fields = {nonce:nonce,token:token,solution:solution,dest:window.location.href};
          for(var k in fields){
            var inp = document.createElement("input");
            inp.type="hidden";inp.name=k;inp.value=fields[k];
            form.appendChild(inp);
          }
          document.body.appendChild(form);
          form.submit();
          return;
        }
      }
      // Update progress (approximate)
      var pct = Math.min(95, (counter/500000)*100);
      bar.style.width = pct + "%%";
      status.textContent = "Verifying... (" + Math.floor(counter/1000) + "k attempts)";
      if(counter > 10000000){
        status.textContent = "Verification failed. Please try again.";
        status.className = "status fail";
        return;
      }
      requestAnimationFrame(solve);
    });
  }

  // Start after short delay (let page render)
  setTimeout(solve, 200);
})();
</script>
</body>
</html>`
