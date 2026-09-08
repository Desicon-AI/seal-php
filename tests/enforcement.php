<?php
namespace Desicon\Seal;
require __DIR__.'/contract.php';
$rule=$argv[1]; $action=$argv[2];
$paths=['honeypot'=>'/.env','sqli'=>'/?q=UNION%20SELECT','xss'=>'/?q=%3Cscript%3E'];
$types=['honeypot'=>'HONEYPOT_ACCESS','sqli'=>'SQL_INJECTION','xss'=>'XSS_ATTACK'];
$config=new \ReflectionProperty(Client::class,'defaultWaf');$config->setAccessible(true);$waf=$config->getValue();$waf[$rule]['action']=$action;
setClient('wafConfig',$waf);setClient('apiKey','synthetic');
$_SERVER=['REQUEST_METHOD'=>'GET','REQUEST_URI'=>$paths[$rule],'REMOTE_ADDR'=>'127.0.0.1','HTTP_USER_AGENT'=>'Browser'];
http_response_code(200);
register_shutdown_function(function()use($action,$rule,$types){
 check(http_response_code()===($action==='drop'?403:200),'Unexpected HTTP outcome');
 $body=json_decode(end($GLOBALS['calls'])->options[CURLOPT_POSTFIELDS],true);
 check(strpos(json_encode($body),$types[$rule])!==false,'Missing signal');
 check(strpos(json_encode($body),$action==='drop'?'blocked':'observed')!==false,'Wrong recorded action');
 echo "Enforcement check passed\n";
});
invoke('runSecurityEngine');
check($action==='report','Blocking did not stop the request');
