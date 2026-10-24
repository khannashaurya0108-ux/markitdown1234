const {selfTests}=require('./detector.js');let f=0;const T=selfTests();
for(const [n,ok] of T){console.log((ok?'PASS':'FAIL')+': '+n);if(!ok)f++}
console.log(`\n${T.length-f}/${T.length} passed`);process.exit(f?1:0);
