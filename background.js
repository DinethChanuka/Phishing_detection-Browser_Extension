// background.js - Advanced ML email threat scoring engine (optimized with new rules)
'use strict';

// ─── EMBEDDED CONFIGURATION DATA ──────────────────────────────────────────
const EMBEDDED_CONFIG = {
  keywords: {
    red: ["verify","urgent","password","click here","account suspended","security alert","unusual activity","confirm your identity","update payment","wire transfer","login to verify","deactivation","irs","lottery","inheritance","phishing","immediate action","suspended","locked","unauthorized","breach","compromised","reactivate","validate","verification required","account closure","reset password","security breach","urgent response needed","act now","limited access","unauthorized login","fraud alert","account disabled","reconfirm","identity check","bank alert","payment failed","billing issue","verify now","critical alert","important notice","final warning","last chance","time sensitive","account issue","update details","re-authenticate","access denied","restricted access","suspicious activity","security issue","account risk","login attempt","failed login","recovery required","unlock account","sensitive information","data breach","compromise detected","system alert","account compromised","security verification","action required","verify account","reconfirm identity","account verification","urgent alert","security notice","warning notice","fraud detected","illegal activity","report immediately","account freeze","account locked","verify billing","payment verification","critical update","system compromised","urgent verification","account alert","confirm account","security validation","identity verification","verification needed","urgent login","security check","important alert","system warning","unauthorized access","data leak","account breach","security failure","login issue","payment alert","risk detected","security risk"],
    yellow: ["invoice","receipt","shipping","order","tracking","subscription","free","discount","offer","congratulations","prize","newsletter","statement","overdue","payment required","upgrade","limited time","bonus","cashback","reward","exclusive","opportunity","special offer","promo","deal","save now","best price","limited offer","sale","flash sale","big savings","free trial","trial period","join now","subscribe now","member offer","discount code","voucher","coupon","clearance","promotion","hot deal","gift","giveaway","win now","entry","survey","feedback","rating","review","order confirmation","delivery update","shipment","dispatch","tracking number","billing","payment due","invoice attached","receipt attached","order shipped","order delivered","membership","renewal","auto-renew","subscription update","upgrade now","downgrade","plan change","account update","service notice","notification","reminder","due date","late fee","balance","credit","refund","rebate","cash offer","loyalty","points","earn points","exclusive deal","special promotion","limited stock","hurry up","don't miss","act fast","early access","vip offer","seasonal sale","holiday deal","bundle","combo offer","discounted","price drop","featured deal"]
  },
  disposableDomains: new Set(["mailinator.com","guerrillamail.com","tempmail.com","10minutemail.com","throwawaymail.com","sharklasers.com","yopmail.com","temp-mail.org","mailnator.com","spamgourmet.com","trashmail.com","guerrillamail.net","mailcatch.com","fakeinbox.com","dispostable.com","getairmail.com","maildrop.cc","mintemail.com","emailondeck.com","tempinbox.com","mailnesia.com","spam4.me","moakt.com","incognitomail.org","temporary-mail.net","instant-mail.de","emailfake.com","mohmal.com","tempmailo.com","mailtemp.net","fakemail.net","trashmail.net","mailnull.com","anonbox.net","mailimate.com","tempemail.net","getnada.com","mailinator.net","trashmail.org","tempail.com","tempr.email","mailpoof.com","temp-mail.io","emailtemporario.com.br","dropmail.me","mail7.io","spambog.com","mailboxy.fun","trashmail.de","mytemp.email","mintmail.com","tempmailer.com","fakemailgenerator.com","temp-mail.live","temporarymail.com","mailtemp.org","mailtothis.com","tempinbox.net","temporaryinbox.com","inboxalias.com","tempmail.dev","spambox.us","emailtemp.org","emailfake.org","tempmailbox.org","mailforspam.com","mailfreeonline.com","spamfree24.org","mailtemp.info","tempmailaddress.com","spamgourmet.net","emailfake.net","temp-mail.top","tempmail.email","disposableinbox.com","mailin8r.com","mail-temp.com","tempmailhub.com","mailhazard.com","mail-temp.net","mailtemp.email","temp-mail.co","mailjunkie.com","temp-mail.xyz","spamtrail.com","emailtemporanea.net","mail-temp.org","mail-temp.xyz","temp-mail.site","temp-mail.club","mail-temp.club","temp-mail.biz","mail-temp.biz","tempmail.biz","temp-mail.us","mail-temp.us","tempmail.us","mail-temp.info","temp-mail.info","tempmail.info","temp-mail.app","mail-temp.app","tempmail.app","temp-mail.pro","mail-temp.pro","tempmail.pro","temp-mail.store","mail-temp.store","tempmail.store","temp-mail.space","mail-temp.space","tempmail.space","temp-mail.tech","mail-temp.tech","tempmail.tech","temp-mail.online","mail-temp.online","tempmail.online","temp-mail.digital","mail-temp.digital","tempmail.digital","temp-mail.cloud","mail-temp.cloud","tempmail.cloud","temp-mail.email","mail-temp.email","tempmail.email","temp-mail.services","mail-temp.services","tempmail.services","temp-mail.systems","mail-temp.systems","tempmail.systems","temp-mail.network","mail-temp.network","tempmail.network","temp-mail.world","mail-temp.world","tempmail.world","temp-mail.today","mail-temp.today","tempmail.today","temp-mail.life","mail-temp.life","tempmail.life","temp-mail.zone","mail-temp.zone","tempmail.zone","temp-mail.global","mail-temp.global","tempmail.global","temp-mail.center","mail-temp.center","tempmail.center","temp-mail.group","mail-temp.group","tempmail.group","temp-mail.support","mail-temp.support","tempmail.support","temp-mail.company","mail-temp.company","tempmail.company","temp-mail.agency","mail-temp.agency","tempmail.agency","temp-mail.solutions","mail-temp.solutions","tempmail.solutions","temp-mail.consulting","mail-temp.consulting","tempmail.consulting","temp-mail.marketing","mail-temp.marketing","tempmail.marketing","temp-mail.media","mail-temp.media","tempmail.media","temp-mail.events","mail-temp.events","tempmail.events","temp-mail.tools","mail-temp.tools","tempmail.tools","temp-mail.design","mail-temp.design","tempmail.design","temp-mail.software","mail-temp.software","tempmail.software","temp-mail.engineering","mail-temp.engineering","tempmail.engineering"]),
  typosquatPatterns: ["paypa1","paypaI","paypol","paypall","pay-pal","paypaal","payp4l","payp@l","g00gle","go0gle","gogle","goog1e","googIe","goggle","gooogle","g0ogle","rnicrosoft","micros0ft","m1crosoft","micr0soft","microsofft","microsfot","micro-soft","micros0ft-login","amaz0n","am4zon","amazoon","amzon","amazn","amaazon","amazonn","amaz0n-secure","faceb00k","facebo0k","facebok","f4cebook","faccebook","faceebook","facebookk","faceb00k-login","paypal-verify","paypal-secure","paypal-login","paypal-update","paypal-alert","paypal-confirm","paypal-check","paypal-security","secure-login","secure-login-now","secure-access","secure-account","secure-check","secure-update","secure-verification","secure-alert","account-verify","account-verification","account-check","account-update","account-alert","account-secure","account-confirm","account-login","verify-paypal","verify-account","verify-now","verify-login","verify-secure","verify-update","verify-info","verify-access","microsoft-support","microsoft-login","microsoft-secure","microsoft-update","microsoft-alert","microsoft-verify","microsoft-account","microsoft-check","appleid-verify","appleid-login","appleid-secure","appleid-update","appleid-alert","appleid-confirm","appleid-check","appleid-security","amazon-security","amazon-login","amazon-update","amazon-alert","amazon-verify","amazon-check","amazon-confirm","amazon-secure","google-verify","google-login","google-update","google-alert","google-secure","google-check","google-confirm","google-account","dropbox-login","dropbox-secure","dropbox-update","dropbox-alert","dropbox-verify","dropbox-check","dropbox-confirm","dropbox-account","bankofamerica-verify","bankofamerica-login","bankofamerica-secure","bankofamerica-update","bankofamerica-alert","bankofamerica-check","bankofamerica-confirm","bankofamerica-account","login-secure","login-verify","login-alert","login-update","login-check","login-confirm","login-required","login-warning","update-now","update-account","update-payment","update-info","update-details","update-secure","update-required","update-alert","security-alert","security-check","security-update","security-warning","security-notice","security-required","security-confirm","security-login","password-reset","password-update","password-alert","password-check","password-secure","password-required","password-change","password-confirm","bank-login","bank-secure","bank-update","bank-alert","bank-check","bank-confirm","bank-verify","bank-account","creditcard-login","creditcard-secure","creditcard-update","creditcard-alert","creditcard-check","creditcard-confirm","creditcard-verify","creditcard-account","billing-update","billing-alert","billing-check","billing-confirm","billing-secure","billing-verify","billing-required","billing-login","payment-update","payment-alert","payment-check","payment-confirm","payment-secure","payment-verify","payment-required","payment-login","free-gift","free-offer","free-reward","free-bonus","free-deal","free-access","free-trial","free-prize","gift-card","gift-offer","gift-reward","gift-bonus","gift-deal","gift-access","gift-prize","gift-now","reward-now","reward-offer","reward-bonus","reward-deal","reward-access","reward-prize","reward-alert","reward-update","bonus-now","bonus-offer","bonus-deal","bonus-alert","bonus-update","bonus-access","bonus-prize","bonus-reward","crypto-login","crypto-secure","crypto-update","crypto-alert","crypto-check","crypto-confirm","crypto-verify","crypto-wallet","bitcoin-login","bitcoin-secure","bitcoin-update","bitcoin-alert","bitcoin-check","bitcoin-confirm","bitcoin-verify","bitcoin-wallet","wallet-login","wallet-secure","wallet-update","wallet-alert","wallet-check","wallet-confirm","wallet-verify","wallet-access","delivery-update","delivery-alert","delivery-check","delivery-confirm","delivery-secure","delivery-verify","delivery-status","delivery-track","shipping-update","shipping-alert","shipping-check","shipping-confirm","shipping-secure","shipping-verify","shipping-status","shipping-track","order-update","order-alert","order-check","order-confirm","order-secure","order-verify","order-status","order-track","subscription-update","subscription-alert","subscription-check","subscription-confirm","subscription-secure","subscription-verify","subscription-renew","subscription-login","invoice-update","invoice-alert","invoice-check","invoice-confirm","invoice-secure","invoice-verify","invoice-required","invoice-login","receipt-update","receipt-alert","receipt-check","receipt-confirm","receipt-secure","receipt-verify","receipt-required","receipt-login","support-login","support-secure","support-update","support-alert","support-check","support-confirm","support-verify","support-account","help-login","help-secure","help-update","help-alert","help-check","help-confirm","help-verify","help-account","service-login","service-secure","service-update","service-alert","service-check","service-confirm","service-verify","service-account","confirm-now","confirm-account","confirm-login","confirm-update","confirm-secure","confirm-required","confirm-alert","confirm-access","urgent-login","urgent-update","urgent-alert","urgent-check","urgent-confirm","urgent-verify","urgent-action","urgent-required","action-required","action-needed","action-now","action-alert","action-check","action-confirm","action-secure","action-login","access-login","access-secure","access-update","access-alert","access-check","access-confirm","access-verify","access-required","identity-login","identity-secure","identity-update","identity-alert","identity-check","identity-confirm","identity-verify","identity-required"],
  threatFeed: {
    "malicious-example.com":{risk:"red",score:90},
    "phishing-test.net":{risk:"red",score:85},
    "secure-paypal.xyz":{risk:"red",score:95},
    "login-verify-now.com":{risk:"red",score:88},
    "suspicious-link.org":{risk:"yellow",score:60},
    "free-gift-card.net":{risk:"yellow",score:55},
    "paypal-security-check.com":{risk:"red",score:93},
    "account-verify-alert.net":{risk:"red",score:89},
    "banking-update-required.com":{risk:"red",score:91},
    "secure-login-alert.xyz":{risk:"red",score:94},
    "apple-id-confirmation.net":{risk:"red",score:92},
    "microsoft-reset-password.com":{risk:"red",score:90},
    "amazon-security-warning.org":{risk:"red",score:87},
    "netflix-billing-failed.com":{risk:"red",score:88},
    "crypto-wallet-verification.net":{risk:"red",score:91},
    "update-your-bank-info.com":{risk:"red",score:93},
    "verify-account-now.net":{risk:"red",score:89},
    "urgent-login-action.com":{risk:"red",score:90},
    "security-warning-alert.net":{risk:"red",score:92},
    "account-recovery-check.com":{risk:"red",score:88},
    "password-reset-required.net":{risk:"red",score:91},
    "email-verification-alert.com":{risk:"red",score:90},
    "bank-alert-update.net":{risk:"red",score:93},
    "unauthorized-login-check.com":{risk:"red",score:94},
    "account-suspension-warning.net":{risk:"red",score:92},
    "secure-access-verification.com":{risk:"red",score:91},
    "invoice-payment-reminder.com":{risk:"yellow",score:58},
    "order-tracking-update.net":{risk:"yellow",score:57},
    "free-reward-offer.com":{risk:"yellow",score:54},
    "limited-time-deal.net":{risk:"yellow",score:52},
    "subscription-renewal-alert.com":{risk:"yellow",score:60},
    "discount-coupon-now.net":{risk:"yellow",score:55},
    "promo-offer-exclusive.com":{risk:"yellow",score:53},
    "cashback-reward-alert.net":{risk:"yellow",score:56},
    "shipping-confirmation-update.com":{risk:"yellow",score:59},
    "delivery-status-check.net":{risk:"yellow",score:57},
    "win-big-now.com":{risk:"yellow",score:54},
    "prize-claim-center.net":{risk:"yellow",score:56},
    "survey-reward-offer.com":{risk:"yellow",score:53},
    "exclusive-vip-deal.net":{risk:"yellow",score:55},
    "bonus-reward-program.com":{risk:"yellow",score:57},
    "secure-login-update-alert.com":{risk:"red",score:92},
    "bank-account-verification.net":{risk:"red",score:94},
    "identity-confirmation-required.com":{risk:"red",score:95},
    "urgent-security-update.net":{risk:"red",score:91},
    "account-breach-notice.com":{risk:"red",score:93},
    "offer-ending-soon.net":{risk:"yellow",score:52},
    "discount-sale-alert.com":{risk:"yellow",score:53},
    "cheap-deals-online.net":{risk:"yellow",score:51},
    "flash-sale-now.com":{risk:"yellow",score:54},
    "limited-offer-deals.net":{risk:"yellow",score:55},
    "verify-billing-info-now.com":{risk:"red",score:92},
    "payment-failed-alert.net":{risk:"red",score:90},
    "update-card-details.com":{risk:"red",score:91},
    "banking-login-verification.net":{risk:"red",score:93},
    "secure-checkout-alert.com":{risk:"red",score:89},
    "secure-login-update.example.com":{risk:"red",score:95},
    "account-verify-now.security-alert.net":{risk:"red",score:92},
    "login-confirmation-required.user-check.org":{risk:"red",score:90},
    "update-your-password.immediate-action.co":{risk:"red",score:91},
    "banking-alert.verify-account.net":{risk:"red",score:93},
    "paypal-secure-login.fake-domain.org":{risk:"red",score:96},
    "google-account-warning.security-check.net":{risk:"red",score:94},
    "amazon-verification-required.alert-user.co":{risk:"red",score:92},
    "microsoft-account-reset.security-alert.org":{risk:"red",score:93},
    "icloud-login-confirmation.user-auth.net":{risk:"red",score:91},
    "secure-access-paypa1.com":{risk:"red",score:98},
    "g00gle-account-verify.net":{risk:"red",score:97},
    "micr0soft-login-alert.org":{risk:"red",score:96},
    "amaz0n-security-check.co":{risk:"red",score:95},
    "faceb00k-authentication.net":{risk:"red",score:94},
    "app1e-id-login.org":{risk:"red",score:93},
    "netfl1x-account-update.co":{risk:"red",score:92},
    "instagrarn-verification.net":{risk:"red",score:91},
    "twltter-login-alert.org":{risk:"red",score:90},
    "linkedln-security-check.co":{risk:"red",score:89},
    "paypal.com.secure-login.fake-site.net":{risk:"red",score:99},
    "google.com.account-verify.security-alert.org":{risk:"red",score:98},
    "amazon.com.login-required.user-check.net":{risk:"red",score:97},
    "microsoft.com.password-reset.fake-domain.co":{risk:"red",score:96},
    "apple.com.verify-now.security-check.org":{risk:"red",score:95},
    "bit.ly":{risk:"yellow",score:65},
    "tinyurl.com":{risk:"yellow",score:65},
    "shorturl.at":{risk:"yellow",score:65},
    "goo.su":{risk:"yellow",score:70},
    "cutt.ly":{risk:"yellow",score:65},
    "urgent-account-action.required-now.net":{risk:"red",score:94},
    "verify-immediately.security-warning.org":{risk:"red",score:93},
    "account-suspended.fix-now.co":{risk:"red",score:92},
    "unauthorized-login-attempt.alert-user.net":{risk:"red",score:95},
    "confirm-identity-now.user-check.org":{risk:"red",score:91},
    "secure-banking-login.update-info.net":{risk:"red",score:93},
    "crypto-wallet-login.verify-now.org":{risk:"red",score:96},
    "exchange-account-security.alert.co":{risk:"red",score:92},
    "payment-failed-update-info.net":{risk:"red",score:90},
    "invoice-overdue-check-now.org":{risk:"red",score:89},
    "email-login-verification.secure-access.net":{risk:"red",score:91},
    "cloud-storage-password-reset.alert-user.co":{risk:"red",score:92},
    "system-admin-message.verify-now.org":{risk:"red",score:93},
    "support-team-alert.account-check.net":{risk:"red",score:90},
    "helpdesk-login-confirm.security-alert.org":{risk:"red",score:91},
    "user-authentication-required.verify-now.net":{risk:"red",score:92},
    "login-to-restore-access.account-check.org":{risk:"red",score:93},
    "reactivate-account-now.security-alert.co":{risk:"red",score:91},
    "final-warning-account-suspension.net":{risk:"red",score:95},
    "limited-access-fix-immediately.org":{risk:"red",score:94}
  },
  trustedSenders: {
    domains: new Set(["google.com","microsoft.com","paypal.com","amazon.com","apple.com","dropbox.com","github.com","linkedin.com","twitter.com","facebook.com","instagram.com","reddit.com","youtube.com","whatsapp.com","openai.com","bing.com","yahoo.com","outlook.com","live.com","office.com","skype.com","teams.microsoft.com","netflix.com","spotify.com","twitch.tv","pinterest.com","snapchat.com","tiktok.com","discord.com","zoom.us","slack.com","cloudflare.com","digitalocean.com","aws.amazon.com","azure.microsoft.com","firebase.google.com","stackoverflow.com","medium.com","quora.com","wikipedia.org","bbc.com","cnn.com","nytimes.com","theguardian.com","forbes.com","bloomberg.com","reuters.com","aljazeera.com","ebay.com","aliexpress.com","walmart.com","target.com","bestbuy.com","etsy.com","newegg.com","flipkart.com","rakuten.com","shopify.com","stripe.com","visa.com","mastercard.com","americanexpress.com","discover.com","paypalobjects.com","squareup.com","wise.com","payoneer.com","skrill.com","hdfcbank.com","hsbc.com","citibank.com","bankofamerica.com","wellsfargo.com","chase.com","barclays.co.uk","standardchartered.com","dbs.com","ocbc.com","coursera.org","udemy.com","edx.org","khanacademy.org","udacity.com","futurelearn.com","skillshare.com","pluralsight.com","codecademy.com","datacamp.com","airbnb.com","uber.com","booking.com","expedia.com","trip.com","agoda.com","lyft.com","ola.com","grab.com","kayak.com","adobe.com","canva.com","figma.com","corel.com","autodesk.com","blender.org","sketch.com","invisionapp.com","pixlr.com","photopea.com","intel.com","amd.com","nvidia.com","arm.com","qualcomm.com","broadcom.com","tsmc.com","ibm.com","oracle.com","sap.com","samsung.com","huawei.com","xiaomi.com","oppo.com","vivo.com","oneplus.com","sony.com","lg.com","panasonic.com","dell.com","hp.com","lenovo.com","acer.com","asus.com","msi.com","razer.com","toshiba.com","fujitsu.com","nec.com","sharp.co.jp","mozilla.org","opera.com","brave.com","vivaldi.com","duckduckgo.com","startpage.com","proton.me","protonmail.com","tutanota.com","zoho.com","telegram.org","signal.org","messenger.com","line.me","wechat.com","kakao.com","imo.im","viber.com","threema.ch","wire.com","notion.so","evernote.com","trello.com","asana.com","monday.com","clickup.com","basecamp.com","airtable.com","coda.io","todoist.com","mailchimp.com","sendgrid.com","constantcontact.com","campaignmonitor.com","getresponse.com","hubspot.com","marketo.com","salesforce.com","intercom.com","zendesk.com","yelp.com","tripadvisor.com","zomato.com","ubereats.com","doordash.com","grubhub.com","deliveroo.co.uk","foodpanda.com","justeat.com","swiggy.com","imdb.com","rottentomatoes.com","metacritic.com","letterboxd.com","allmusic.com","last.fm","soundcloud.com","deezer.com","pandora.com","tidal.com","nasa.gov","whitehouse.gov","europa.eu","who.int","un.org","worldbank.org","imf.org","wto.org","fao.org","unesco.org","gov.lk","cbsl.gov.lk","icta.lk","moe.gov.lk","health.gov.lk","police.lk","customs.gov.lk","immigration.gov.lk","parliament.lk","supremecourt.lk","google.co.uk","google.lk","google.in","amazon.co.uk","amazon.in","facebook.co.uk","microsoft.co.uk","apple.co.uk","paypal.co.uk","youtube.co.uk","bbc.co.uk","gov.uk","nhs.uk","tesco.com","argos.co.uk","sainsburys.co.uk","asda.com","johnlewis.com","boots.com","currys.co.uk","flipkart.in","paytm.com","phonepe.com","olaelectric.com","reliancejio.com","airtel.in","vodafone.in","bsnl.co.in","irctc.co.in","licindia.in","dialog.lk","mobitel.lk","hutch.lk","airtel.lk","keells.com","cargillsceylon.com","singer.lk","daraz.lk","pickme.lk","ikman.lk","accounts.google.com","myaccount.google.com"]),
    emails: new Set(["security@google.com","noreply@paypal.com","account@amazon.com","no-reply@accounts.google.com","support@microsoft.com","security@apple.com","help@dropbox.com","support@github.com","notifications@linkedin.com","info@facebook.com","security@instagram.com","contact@twitter.com","noreply@reddit.com","support@netflix.com","no-reply@spotify.com","help@twitch.tv","support@discord.com","no-reply@zoom.us","feedback@slack.com","billing@stripe.com","support@visa.com","help@mastercard.com","support@bankofamerica.com","help@hsbc.com","support@coursera.org","no-reply@udemy.com","support@airbnb.com","help@uber.com","support@adobe.com","help@canva.com","support@intel.com","support@amd.com","support@samsung.com","support@huawei.com","support@mozilla.org","help@opera.com","support@telegram.org","support@signal.org","support@notion.so","support@trello.com","support@mailchimp.com","support@sendgrid.com","support@shopify.com","support@squareup.com","info@gov.lk","contact@cbsl.gov.lk","info@health.gov.lk","support@dialog.lk","support@mobitel.lk","support@hutch.lk","support@airtel.lk","info@keells.com","info@cargillsceylon.com","support@singer.lk","support@daraz.lk","support@pickme.lk","support@ikman.lk","no-reply@google.com","googledev-noreply@google.com"])
  },
  mlWeights: {
    weights: { sender_reputation: 0.28, keyword_match: 0.40, link_risk: 0.32 },
    thresholds: { red: 55, yellow: 30 }
  }
};

// ─── CONFIG DEFAULTS ────────────────────────────────────────────────────────
let config = {
  keywords: EMBEDDED_CONFIG.keywords,
  disposableDomains: EMBEDDED_CONFIG.disposableDomains,
  typosquatPatterns: EMBEDDED_CONFIG.typosquatPatterns,
  threatFeed: EMBEDDED_CONFIG.threatFeed,
  trustedSenders: EMBEDDED_CONFIG.trustedSenders,
  mlWeights: EMBEDDED_CONFIG.mlWeights
};

let sensitivity = 'medium';

// ─── STATIC LOOKUP SETS ──────────────────────────────────────────────────────
const FREE_EMAIL_PROVIDERS = new Set([
  'gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'aol.com',
  'icloud.com', 'mail.com', 'live.com', 'msn.com', 'ymail.com',
  'yahoo.co.uk', 'yahoo.co.in', 'googlemail.com', 'me.com'
]);

const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'short.io', 'tiny.cc',
  'is.gd', 'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'bl.ink',
  'snip.ly', 'clck.ru', 'lnkd.in', 'rb.gy', 'qr.ae', 'db.tt', 'urls.fr',
  'bcvc.me', 'yo.lv', 'v.gd', 'tr.im', 'zi.ma', 'cur.lv', 'fur.ly',
  'ity.im', 'q.gs', 'scrnch.me', 'urlz.fr', 'x.co', 'shrt.co', 'po.st',
  'bit.do', 'prettylinkpro.com', 'link.tl', 'gg.gg', 'goo.su'
]);

const SUSPICIOUS_TLDS = new Set([
  '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.pw', '.top', '.click', '.link',
  '.live', '.stream', '.download', '.win', '.loan', '.men', '.work', '.party',
  '.racing', '.review', '.science', '.country', '.kim', '.cricket', '.webcam',
  '.faith', '.bid', '.trade', '.date', '.ren', '.accountant', '.rocks', '.casa',
  '.rest', '.surf', '.band', '.space', '.fun', '.uno', '.monster', '.wiki',
  '.gdn', '.ooo', '.buzz', '.bar', '.hair', '.makeup', '.tattoo', '.cooking'
]);

const BRAND_IMPERSONATION_KEYWORDS = [
  'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'netflix',
  'instagram', 'dropbox', 'linkedin', 'twitter', 'ebay', 'chase', 'wellsfargo',
  'bankofamerica', 'hsbc', 'citibank', 'barclays', 'secure-login', 'account-verify',
  'login-verify', 'signin-secure', 'support-center', 'helpdesk-alert'
];

const HIGH_RISK_TLDS = new Set(['.xyz', '.top', '.click', '.gq', '.tk', '.ml', '.ga', '.cf']);

// ─── RUNTIME STATE ───────────────────────────────────────────────────────────
const CACHE_TTL_MS = 30 * 60 * 1000;
let threatCache = new Map();
let userWhitelist = new Set();
let userBlacklist = new Set();

// ─── LOAD USER LISTS ─────────────────────────────────────────────────────────
async function loadUserLists() {
  const data = await chrome.storage.local.get(['whitelist', 'blacklist']);
  userWhitelist = new Set(data.whitelist || []);
  userBlacklist = new Set(data.blacklist || []);
}
loadUserLists();

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local') {
    if (changes.whitelist) userWhitelist = new Set(changes.whitelist.newValue || []);
    if (changes.blacklist) userBlacklist = new Set(changes.blacklist.newValue || []);
  }
});

// ─── SENSITIVITY ─────────────────────────────────────────────────────────────
async function loadSensitivity() {
  const { sensitivity: sens } = await chrome.storage.sync.get({ sensitivity: 'medium' });
  sensitivity = sens;
  adjustThresholdsForSensitivity();
}
function adjustThresholdsForSensitivity() {
  const base = config.mlWeights.thresholds;
  switch (sensitivity) {
    case 'low': base.red = 70; base.yellow = 45; break;
    case 'high': base.red = 45; base.yellow = 25; break;
    default: base.red = 55; base.yellow = 30;
  }
}
loadSensitivity();
chrome.storage.sync.onChanged.addListener((changes) => {
  if (changes.sensitivity) {
    sensitivity = changes.sensitivity.newValue;
    adjustThresholdsForSensitivity();
  }
});

// ─── UTILITIES ───────────────────────────────────────────────────────────────
function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
function matchesDomain(domain, pattern) {
  domain = (domain || '').toLowerCase().trim();
  pattern = (pattern || '').toLowerCase().trim();
  return domain === pattern || domain.endsWith('.' + pattern);
}
function extractDomain(url) {
  try {
    const host = new URL(url).hostname;
    return host.replace(/^www\./, '').toLowerCase().trim();
  } catch {
    return (url || '')
      .replace(/^https?:\/\//i, '')
      .replace(/\/.*$/, '')
      .replace(/^www\./, '')
      .toLowerCase()
      .trim();
  }
}
function getSuspiciousTld(domain) {
  for (const tld of SUSPICIOUS_TLDS) if (domain.endsWith(tld)) return tld;
  return null;
}
function countHyphens(domain) { return (domain.match(/-/g) || []).length; }

// ─── NEW: Similarity check for typosquatting ────────────────────────────────
function isSimilarToBrand(domain, brand) {
  const normalizedDomain = domain.toLowerCase().replace(/0/g, 'o').replace(/1/g, 'l').replace(/@/g, 'a');
  const normalizedBrand = brand.toLowerCase();
  return normalizedDomain.includes(normalizedBrand) || 
         normalizedBrand.includes(normalizedDomain) ||
         normalizedDomain === normalizedBrand;
}

// ─── ADVANCED URL FEATURES ──────────────────────────────────────────────────
function getUrlFeatures(url) {
  try {
    const parsed = new URL(url);
    const domain = parsed.hostname;
    const path = parsed.pathname;
    let features = {
      isIP: /^\d{1,3}(\.\d{1,3}){3}$/.test(domain),
      length: url.length,
      dotCount: (domain.match(/\./g) || []).length,
      hyphens: (domain.match(/-/g) || []).length,
      hasSuspiciousTld: !!getSuspiciousTld(domain),
      hasHighRiskTld: HIGH_RISK_TLDS.has(domain.split('.').pop()),
      pathLength: path.length,
      hasMultipleSubdomains: (domain.match(/\./g) || []).length >= 3,
      usesShortener: URL_SHORTENERS.has(domain),
      hasBrandImpersonation: BRAND_IMPERSONATION_KEYWORDS.some(kw => domain.includes(kw)),
      hasLoginPath: path.includes('login') || path.includes('verify') || path.includes('signin') || path.includes('auth'),
      isSuspiciousPort: parsed.port && parsed.port !== '443' && parsed.port !== '80'
    };
    let uniqueChars = new Set(domain.split(''));
    features.entropy = uniqueChars.size / domain.length;
    return features;
  } catch { return { isIP: false, length: 100, dotCount: 2, hyphens: 0, hasSuspiciousTld: false, hasHighRiskTld: false, pathLength: 0, hasMultipleSubdomains: false, usesShortener: false, hasBrandImpersonation: false, hasLoginPath: false, isSuspiciousPort: false, entropy: 0.5 }; }
}

// ─── SENDER SCORING (0–100) ──────────────────────────────────────────────────
function getSenderScore(senderDomain, senderEmail, subject = '') {
  if (!senderDomain) return 48;
  senderDomain = senderDomain.toLowerCase().trim();
  senderEmail = (senderEmail || '').toLowerCase().trim();

  // Explicit safe emails (critical)
  const SAFE_EMAILS = new Set([
    'no-reply@accounts.google.com',
    'googledev-noreply@google.com',
    'no-reply@google.com',
    'security@google.com',
    'accounts@google.com'
  ]);
  if (SAFE_EMAILS.has(senderEmail)) return 0;

  if (userWhitelist.has(senderDomain)) return 0;
  if (userBlacklist.has(senderDomain)) return 100;
  if (config.trustedSenders.domains.has(senderDomain)) return 0;
  if (config.trustedSenders.emails.has(senderEmail)) return 0;
  if (config.disposableDomains.has(senderDomain)) return 75;

  for (const pattern of config.typosquatPatterns)
    if (senderDomain.includes(pattern.toLowerCase())) return 88;

  for (const [domain, data] of Object.entries(config.threatFeed))
    if (matchesDomain(senderDomain, domain)) return clamp(data.score, 0, 100);

  let score = FREE_EMAIL_PROVIDERS.has(senderDomain) ? 18 : 32;
  
  // NEW: Free email pretending to be company
  if (FREE_EMAIL_PROVIDERS.has(senderDomain)) {
    const companyKeywords = ['bank', 'paypal', 'amazon', 'google', 'microsoft', 'apple', 'security', 'verify'];
    if (companyKeywords.some(kw => subject.toLowerCase().includes(kw))) {
      score = Math.max(score, 45);
    }
  }
  
  if (getSuspiciousTld(senderDomain)) score = Math.max(score, 58);
  if (senderDomain.startsWith('xn--')) score = Math.max(score, 68);
  const hyphens = countHyphens(senderDomain);
  if (hyphens >= 3) score = Math.max(score, 55);
  else if (hyphens === 2) score = Math.max(score, 40);
  if (senderDomain.length > 40) score = Math.max(score, 48);
  for (const brand of BRAND_IMPERSONATION_KEYWORDS)
    if (senderDomain.includes(brand)) { score = Math.max(score, 72); break; }
    
  // NEW: Typosquat similarity check
  for (const brand of ['paypal', 'google', 'amazon', 'microsoft', 'apple', 'facebook']) {
    if (isSimilarToBrand(senderDomain, brand) && !config.trustedSenders.domains.has(brand + '.com')) {
      score = Math.max(score, 75);
      break;
    }
  }
  
  return clamp(score, 0, 100);
}

// ─── KEYWORD SCORING (0–100) ─────────────────────────────────────────────────
function getKeywordScore(subjectText, bodyText, isTrustedSender = false) {
  const subject = (subjectText || '').toLowerCase();
  const body = (bodyText || '').toLowerCase();
  let redSubject = 0, redBody = 0, yellowHits = 0;
  let hasUrgent = false;
  let hasAction = false;
  
  for (const kw of config.keywords.red) {
    const k = kw.toLowerCase();
    if (subject.includes(k)) redSubject++;
    if (body.includes(k)) redBody++;
    if (k === 'urgent' || k === 'immediate action' || k === 'act now' || k === 'time sensitive') hasUrgent = true;
    if (k === 'click here' || k === 'verify' || k === 'confirm' || k === 'login') hasAction = true;
  }
  for (const kw of config.keywords.yellow) {
    const k = kw.toLowerCase();
    if (subject.includes(k) || body.includes(k)) yellowHits++;
  }
  
  const totalRed = redSubject + redBody;
  if (totalRed === 0 && yellowHits === 0) return 0;
  
  // NEW: Urgency + Action combo rule
  let urgencyBonus = 0;
  if (hasUrgent && hasAction) urgencyBonus = 20;
  
  if (totalRed > 0) {
    const weightedRed = redSubject * 2 + redBody;
    let base = isTrustedSender ? 40 : 55;
    let compound = Math.min(weightedRed - 1, 6) * 5;
    const yBonus = Math.min(yellowHits, 4) * 1;
    let score = base + compound + yBonus + urgencyBonus;
    if (isTrustedSender && totalRed === 1) score = Math.min(score, 45);
    return clamp(score, 0, isTrustedSender ? 75 : 96);
  }
  let base = 20;
  let compound = Math.min(yellowHits - 1, 5) * 3;
  let score = base + compound + (urgencyBonus / 2);
  if (isTrustedSender) score = Math.min(score, 35);
  return clamp(score, 0, isTrustedSender ? 40 : 54);
}

// ─── LINK SCORING (0–100) ────────────────────────────────────────────────────
async function getLinkScore(url, senderDomain = null, linkText = null) {
  const domain = extractDomain(url);
  if (!domain) return 10;
  if (userWhitelist.has(domain)) return 0;
  if (userBlacklist.has(domain)) return 100;
  if (config.trustedSenders.domains.has(domain)) return 0;

  const cached = threatCache.get(domain);
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL_MS) return cached.score;

  let score = 10;
  const features = getUrlFeatures(url);
  
  for (const [pattern, data] of Object.entries(config.threatFeed))
    if (matchesDomain(domain, pattern)) { score = clamp(data.score, 0, 100); break; }

  if (score <= 10) {
    if (features.isIP) score = Math.max(score, 85);
    if (features.usesShortener) score = Math.max(score, 70);
    if (features.hasSuspiciousTld) score = Math.max(score, 60);
    if (features.hasHighRiskTld) score = Math.max(score, 75);
    if (features.hasMultipleSubdomains) score = Math.max(score, 55);
    if (features.hasBrandImpersonation) score = Math.max(score, 80);
    if (features.hyphens >= 3) score = Math.max(score, 65);
    if (features.length > 80) score = Math.max(score, 50);
    if (features.entropy > 0.8) score = Math.max(score, 45);
    if (features.hasLoginPath) score = Math.max(score, 50);
    if (features.isSuspiciousPort) score = Math.max(score, 60);
    
    // NEW: Sender-Link mismatch rule
    if (senderDomain && !domain.includes(senderDomain) && !domain.includes(senderDomain.replace(/^www\./, ''))) {
      // Check if sender domain is a known brand and link domain doesn't match
      const isBrandSender = BRAND_IMPERSONATION_KEYWORDS.some(brand => senderDomain.includes(brand));
      if (isBrandSender) {
        score = Math.max(score, 70);
      } else {
        score = Math.max(score, 40);
      }
    }
    
    // NEW: Link text vs URL mismatch
    if (linkText) {
      const linkTextDomain = extractDomain(linkText);
      if (linkTextDomain && linkTextDomain !== domain && !domain.includes(linkTextDomain)) {
        score = Math.max(score, 55);
      }
    }
    
    for (const pattern of config.typosquatPatterns)
      if (domain.includes(pattern.toLowerCase())) { score = Math.max(score, 90); break; }
  }
  score = clamp(score, 0, 100);
  const { red, yellow } = config.mlWeights.thresholds;
  const risk = score >= red ? 'red' : score >= yellow ? 'yellow' : 'green';
  threatCache.set(domain, { score, risk, timestamp: Date.now() });
  return score;
}

// ─── COMPOSITE EMAIL RISK ANALYSIS ───────────────────────────────────────────
async function analyzeEmail(emailData) {
  const senderScore = getSenderScore(emailData.senderDomain, emailData.senderEmail, emailData.subject);
  const isTrusted = (senderScore === 0);
  let keywordScore = getKeywordScore(emailData.subject, emailData.snippet, isTrusted);
  let linkScore = emailData.linkScores?.length ? Math.max(...emailData.linkScores) : 0;
  
  // NEW: Too many links rule
  if (emailData.linkUrls && emailData.linkUrls.length > 5) {
    linkScore = Math.min(linkScore + 20, 100);
  }
  
  // NEW: Brand impersonation in subject
  const brandImpersonation = BRAND_IMPERSONATION_KEYWORDS.some(brand => 
    emailData.subject.toLowerCase().includes(brand) || emailData.snippet.toLowerCase().includes(brand)
  );
  if (brandImpersonation) {
    keywordScore = Math.min(keywordScore + 15, 100);
  }

  const { sender_reputation: wS, keyword_match: wK, link_risk: wL } = config.mlWeights.weights;
  let totalScore = Math.round(senderScore * wS + keywordScore * wK + linkScore * wL);
  if (senderScore >= 85) totalScore = Math.max(totalScore, 72);
  if (linkScore >= 82) totalScore = Math.max(totalScore, 67);
  const elevatedSender = senderScore >= 50, elevatedKeyword = keywordScore >= 62, elevatedLink = linkScore >= 50;
  const signalCount = [elevatedSender, elevatedKeyword, elevatedLink].filter(Boolean).length;
  if (signalCount === 2) totalScore = Math.max(totalScore, 40);
  if (signalCount === 3) totalScore = Math.max(totalScore, 68);
  if (senderScore >= 70 && keywordScore >= 62) totalScore = Math.max(totalScore, 48);
  if (linkScore >= 58 && keywordScore >= 62) totalScore = Math.max(totalScore, 45);
  if (FREE_EMAIL_PROVIDERS.has(emailData.senderDomain) && linkScore >= 50) totalScore = Math.max(totalScore, 42);
  
  // NEW: Sender-Link mismatch combined score
  if (emailData.senderDomain && emailData.linkUrls && emailData.linkUrls.length > 0) {
    let mismatchCount = 0;
    for (const url of emailData.linkUrls) {
      const linkDomain = extractDomain(url);
      if (linkDomain && !linkDomain.includes(emailData.senderDomain) && 
          !emailData.senderDomain.includes(linkDomain) &&
          BRAND_IMPERSONATION_KEYWORDS.some(brand => emailData.senderDomain.includes(brand))) {
        mismatchCount++;
      }
    }
    if (mismatchCount > 0) {
      totalScore = Math.min(totalScore + (mismatchCount * 10), 100);
    }
  }
  
  totalScore = clamp(totalScore, 0, 100);
  const { red, yellow } = config.mlWeights.thresholds;
  const risk = totalScore >= red ? 'red' : totalScore >= yellow ? 'yellow' : 'green';
  return { risk, score: totalScore, components: { senderScore, keywordScore, linkScore }, signalCount };
}

// ─── BATCH PROCESSORS ────────────────────────────────────────────────────────
async function analyzeEmailBatch(emails) {
  const results = [];
  for (const email of emails) {
    try {
      const analysis = await analyzeEmail(email);
      results.push({ rowId: email.rowId, ...analysis });
      await updateStats(analysis.risk);
    } catch (e) { console.error(e); }
  }
  return results;
}
async function analyzeLinkBatch(links) {
  const promises = links.map(async (item) => {
    try {
      const score = await getLinkScore(item.url, item.senderDomain, item.linkText);
      const { red, yellow } = config.mlWeights.thresholds;
      const risk = score >= red ? 'red' : score >= yellow ? 'yellow' : 'green';
      return { elementId: item.elementId, risk, score, url: item.url };
    } catch (e) { return null; }
  });
  const results = (await Promise.all(promises)).filter(r => r !== null);
  for (const res of results) await updateStats(res.risk);
  return results;
}

// ─── STATS (batched) ─────────────────────────────────────────────────────────
let statsBuffer = { green: 0, yellow: 0, red: 0, total: 0 };
let statsTimeout = null;
async function updateStats(risk) {
  statsBuffer[risk] = (statsBuffer[risk] || 0) + 1;
  statsBuffer.total++;
  if (statsTimeout) clearTimeout(statsTimeout);
  statsTimeout = setTimeout(async () => {
    try {
      const data = await chrome.storage.local.get(['stats']);
      const current = data.stats || { green: 0, yellow: 0, red: 0, total: 0 };
      const newStats = {
        green: current.green + statsBuffer.green,
        yellow: current.yellow + statsBuffer.yellow,
        red: current.red + statsBuffer.red,
        total: current.total + statsBuffer.total
      };
      await chrome.storage.local.set({ stats: newStats });
      statsBuffer = { green: 0, yellow: 0, red: 0, total: 0 };
    } catch (e) { console.error(e); }
  }, 2000);
}

// ─── CACHE MAINTENANCE ───────────────────────────────────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [key, val] of threatCache) if (now - val.timestamp > CACHE_TTL_MS) threatCache.delete(key);
}, 10 * 60 * 1000);

// ─── MESSAGE HANDLER ─────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  switch (request.type) {
    case 'analyzeLinks':
      analyzeLinkBatch(request.links).then(results =>
        sendResponse({ results: results.map(r => [r.elementId, { risk: r.risk, score: r.score, url: r.url }]) })
      );
      return true;
    case 'analyzeEmails':
      analyzeEmailBatch(request.emails).then(results => sendResponse({ results }));
      return true;
    case 'reportFalsePositive':
      if (request.domain) {
        userWhitelist.add(request.domain.toLowerCase().trim());
        chrome.storage.local.set({ whitelist: Array.from(userWhitelist) });
      }
      sendResponse({ success: true });
      return true;
    case 'reportFalseNegative':
      if (request.domain) {
        userBlacklist.add(request.domain.toLowerCase().trim());
        chrome.storage.local.set({ blacklist: Array.from(userBlacklist) });
      }
      sendResponse({ success: true });
      return true;
    case 'getStats':
      chrome.storage.local.get(['stats'], data => sendResponse(data.stats || { green: 0, yellow: 0, red: 0, total: 0 }));
      return true;
    case 'clearCache':
      threatCache.clear();
      sendResponse({ success: true });
      return true;
    default: return false;
  }
});