<?php
namespace Desicon\Seal;
require __DIR__ . '/../src/Client.php';

foreach (['CURLOPT_CUSTOMREQUEST','CURLOPT_POSTFIELDS','CURLOPT_RETURNTRANSFER','CURLOPT_HTTPHEADER','CURLOPT_TIMEOUT','CURLOPT_SSL_VERIFYPEER','CURLOPT_SSL_VERIFYHOST','CURLOPT_NOSIGNAL','CURLINFO_HTTP_CODE'] as $i => $name) {
    if (!defined($name)) define($name, $i+1000);
}
$GLOBALS['calls']=[]; $GLOBALS['httpStatus']=200; $GLOBALS['testTime']=1000;
function time() { return $GLOBALS['testTime']; }
function curl_init($url) { return (object)['url'=>$url,'options'=>[]]; }
function curl_setopt($ch,$option,$value) { $ch->options[$option]=$value; return true; }
function curl_exec($ch) { $GLOBALS['calls'][]=$ch; return '{"status":"ok"}'; }
function curl_getinfo($ch,$option) { return $GLOBALS['httpStatus']; }
function curl_close($ch) {}
function check($condition,$message) { if (!$condition) throw new \RuntimeException($message); }
function setClient($name,$value) { $property=new \ReflectionProperty(Client::class,$name); $property->setAccessible(true); $property->setValue(null,$value); }
function invoke($name,...$args) { $method=new \ReflectionMethod(Client::class,$name); $method->setAccessible(true); return $method->invoke(null,...$args); }
setClient('apiKey','synthetic'); setClient('signingSecret','synthetic-secret'); setClient('appName','test'); setClient('environment','staging'); setClient('endpoint','https://example.test/custom/sandbox/ingest');
check(Client::sendCronHeartbeat(), 'heartbeat not acknowledged');
$first=end($GLOBALS['calls']);
check($first->url==='https://example.test/custom/ingest/heartbeat','wrong heartbeat route');
check($first->options[CURLOPT_SSL_VERIFYPEER]===true && $first->options[CURLOPT_SSL_VERIFYHOST]===2,'TLS verification disabled');
$body=$first->options[CURLOPT_POSTFIELDS];
check(in_array('X-Seal-Signature: '.hash_hmac('sha256','1000.'.$body,'synthetic-secret'),$first->options[CURLOPT_HTTPHEADER]),'signature/body mismatch');
$GLOBALS['testTime']=1361; Client::sendCronHeartbeat(); $second=end($GLOBALS['calls']);
check(in_array('X-Seal-Timestamp: 1361',$second->options[CURLOPT_HTTPHEADER]),'stale timestamp');
Client::registerDeployment('test2'); check(end($GLOBALS['calls'])->url==='https://example.test/custom/ingest/deployment','wrong deployment route');
$GLOBALS['httpStatus']=503; check(!Client::sendCronHeartbeat(),'HTTP failure reported as success');
$GLOBALS['httpStatus']=200;
$_SERVER=['REQUEST_METHOD'=>'GET','REQUEST_URI'=>'/SECRET-PATH?token=SECRET-QUERY','HTTP_AUTHORIZATION'=>'SECRET-AUTH','HTTP_COOKIE'=>'SECRET-COOKIE','REMOTE_ADDR'=>'127.0.0.1'];
invoke('reportThreat','TEST','127.0.0.1',[]);
check(strpos(end($GLOBALS['calls'])->options[CURLOPT_POSTFIELDS],'SECRET-')===false,'credentials leaked');
setClient('apiKey',null);
setClient('wafConfig',['trustProxyHeaders'=>false,'geoBlocking'=>['blockedCountries'=>[],'action'=>'report'],'maliciousScanners'=>['action'=>'drop'],'methodTampering'=>['action'=>'report'],'payloadOverflow'=>['maxPayloadSize'=>5242880,'action'=>'report'],'pathTraversal'=>['action'=>'report'],'sqli'=>['action'=>'report'],'xss'=>['action'=>'report']]);
foreach (['curl/8','python-requests/2','wget/1'] as $ua) { $_SERVER['HTTP_USER_AGENT']=$ua; $_SERVER['REQUEST_URI']='/api/select/update'; invoke('runSecurityEngine'); }
echo "PHP SDK contract checks passed\n";
