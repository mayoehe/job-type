/**
 * Deterministic synthetic dataset builder — 120 labelled cases:
 *  - 50 fraudulent, 50 legitimate (labels overlap subsets below)
 *  - 20 technically-clean-but-behaviourally-fraudulent (subset "clean-fraud")
 *  - 20 technically-suspicious-but-legitimate (subset "susp-legit")
 * Realistic Indian-context scams: UPI/QR fees, WhatsApp recruiters, fake govt
 * portals, counterfeit offers, APKs; plus EN/Hindi/Marathi/Hinglish variants.
 * Run: node data/build-dataset.js
 */
import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = dirname(fileURLToPath(import.meta.url));
let n = 0;
const rows = [];
const add = (label, subset, url, text, lang = 'en') => rows.push({ id: `JS-${String(++n).padStart(3, '0')}`, label, subset, url, text, lang });

// ---- Fraud templates (varied, multilingual) ----
const fraudTexts = [
  'Dear Candidate, Congratulations! Selected for Infosys work-from-home data entry, salary Rs 85000/month, no interview, instant selection. Pay refundable registration fee Rs 2499 via UPI and share Aadhaar card, PAN card, bank account details plus OTP on WhatsApp within 2 hours. Last chance!',
  'Greetings from placement cell! 100% guaranteed job in TCS for 10th pass, salary Rs 60000. Pay security deposit Rs 1999 (refundable) on given QR code and send Aadhaar number, PAN, passbook photo on Telegram. Offer expires today, act immediately!',
  'सरकारी नौकरी! रेलवे में सीधी भर्ती, बिना परीक्षा नौकरी पक्की। रजिस्ट्रेशन फीस ₹1500 UPI से भरो, आधार नंबर और बैंक विवरण WhatsApp पर भेजो। तुरंत apply करो, offer expires today!',
  'TCS मध्ये घरबसल्या नोकरी! महिना ₹75000, interview नाही, direct joining. नोंदणी शुल्क ₹999 भरा, आधार कार्ड, PAN, बँक तपशील Telegram वर पाठवा आणि OTP sanga. तातडीने apply करा!',
  'Work from home and earn Rs 9000 per day! No experience needed, high salary. Just download our APK, enable AnyDesk access, share UPI PIN and OTP to activate your salary account. Contact WhatsApp only, do not apply on official portal.',
  'Sarkari Naukri 2026: UPSC direct selection without exam! Pay verification fee Rs 1100 (refundable) and share Aadhaar, PAN, cancelled cheque on WhatsApp. Bypass official portal, direct bharti only through our agent. Limited slots!',
  'Dear applicant, your resume selected for HDFC Bank back-office job, salary Rs 55000. Complete background verification by paying Rs 899 training fee via UPI QR, share debit card number + CVV + OTP. Join within 24 hours else offer cancelled.',
  'Flipkart warehouse hiring — 8th pass can apply, salary Rs 52000! Pay placement fee Rs 1499 on PhonePe and message Aadhaar details + bank account on Telegram t.me/fakeagent. Ghar baithe kamao, bina interview selection!',
  'Congratulations, selected for Wipro HR round! Confirm by sharing PAN card, Aadhaar, salary slips, mother name, nominee details, bank statements and OTP for verification. Pay Rs 500 interview scheduling fee. Respond in 1 hour.',
  'Maruti Suzuki direct joining, no qualification needed, salary Rs 65000! Registration charge Rs 1200 refundable. Send photo, signature, Aadhaar, PAN, passport, ration card, bank details to Gmail recruiter. Do not contact company HR directly.',
  'प्रिय उम्मीदवार, घर बैठे कमाएं ₹8000 रोज! सिर्फ WhatsApp पर आधार कार्ड और OTP bhejo, ₹499 joining fee UPI करो। कोई interview नहीं, spot offer! wa.me/91XXXXXXXXXX पर message करो।',
  'प्रिय उमेदवार, अभिनंदन! तुमची निवड झाली आहे. ₹2000 security deposit भरा, आधार नंबर आणि OTP Telegram वर पाठवा. Offer फक्त आजसाठी! Official website वर apply करू नका.',
  'Amazon work-from-home: earn Rs 75000/month, both fresher and experienced can apply. Share bank account, IFSC, Aadhaar, PAN and forward the OTP you receive to our WhatsApp for salary activation. Pay Rs 999 data-charges first.',
  'IBPS bank job confirmed! Pay Rs 2500 processing fee to release your appointment letter, share netbanking password for salary account linking. Contact recruiter on personal Gmail only. Urgent — only 3 seats left!',
  'Accenture hiring girls/boys for back office, salary Rs 48000, no English needed. Pay Rs 799 document verification fee, share Aadhaar + PAN + photo on WhatsApp. Instant selection, joining tomorrow!',
];
const fraudUrls = [
  'https://secure-naukri-verification.xyz/infosys-careers/apply?token=xyz123verify9',
  'https://tcs-jobs-apply.top/careers/join?sessionid=abc99account=1',
  'https://sarkari-job-apply.club/railway-bharti-2026',
  'https://infosys-careers-apply.top/hr/apply',
  'https://bit.ly/3xFakeJobOffer1',
  'https://amaz0n-jobs-apply.xyz/earn-online',
  'https://inf0sys-secure-reg.site/verify',
  'https://xn--nukri-4qa.example.xyz/apply',
  'https://wipro.careers-update-online.club/apply',
  'https://hdfc-bank-kyc-verify.top/offer',
];
// 50 fraud
for (let i = 0; i < 50; i++) {
  const lang = i % 5 === 2 ? 'hi' : i % 5 === 3 ? 'mr' : i % 5 === 4 ? 'hinglish' : 'en';
  add('fraud', i < 20 ? 'clean-fraud' : 'standard',
    i < 20 ? ['https://careers-infosys-apply.com/jobs/2026/apply', 'https://www-tcs-careers.in/jobs/apply', 'https://naukri-verify-portal.com/apply'][i % 3] : fraudUrls[i % fraudUrls.length],
    fraudTexts[i % fraudTexts.length] + ` (Ref #${1000 + i})`, lang);
}

// ---- Legit templates ----
const legitTexts = [
  'Infosys is hiring a Senior React Developer in Bengaluru. Requirements: 4+ years experience, TypeScript, system design. Process: online assessment, two technical interviews, HR round. Apply only via infosys.com/careers. We never ask for fees, OTPs or bank details during application. Contact: careers@infosys.com.',
  'Union Public Service Commission: Civil Services Examination 2026 notification. Eligibility, syllabus and schedule per official notice. Apply at upsconline.nic.in before closing date. Fee payable only through the official portal. See upsc.gov.in.',
  'Tata Motors apprenticeship program: 12th pass/ITI eligible. Stipend as per Apprentices Act. Selection via written test and interview at plant. Apply through the official careers page. No charges at any stage; documents verified in person at joining.',
  'HDFC Bank hiring Probationary Officers through official recruitment. Eligibility: graduate with 50%. Selection: online test + interview. Application only on hdfcbank.com/careers. Bank never asks for OTP, CVV or netbanking passwords.',
  'State Bank of India Specialist Officers recruitment. Vacancy circular on sbi.co.in/careers with reference number. Fee via official payment gateway only. Interviews at designated centres; original documents verified in person after provisional selection.',
  'Cognizant campus drive for 2024/2025 graduates: registration through college placement cell, followed by aptitude test and interviews. Offer letters issued only on company letterhead and verifiable via the candidate portal. No fees.',
  'Marathi: पुणे महानगरपालिका भरती — अधिकृत संकेतस्थळावर जाहिरात, अर्ज फक्त online portal वर. कोणतेही शुल्क WhatsApp वर घेतले जात नाही. मूळ कागदपत्रे प्रत्यक्ष पडताळणीसाठी.',
  'Hindi: SSC GD Constable भर्ती — आधिकारिक नोटिस ssc.gov.in पर देखें। आवेदन केवल आधिकारिक पोर्टल से, फीस भी वहीं। दस्तावेज़ DV राउंड में मूल रूप में देखे जाते हैं; OTP/पिन कभी नहीं मांगा जाता।',
  'Accenture Associate Software Engineer: BE/BTech 2025 batch, selection via cognitive + coding assessment and interviews. Apply on accenture.com. We never request bank details or payments from candidates.',
  'Naukri.com job posting by verified recruiter with company profile, official email domain and interview venue. Salary range stated with experience criteria. Candidates advised to verify via employer website before sharing documents.',
  'Junior Accounts Assistant needed in Pune. Walk-in interview Saturday 10am-2pm at registered office address with resume and originals for verification. No advance payment; salary via bank transfer after joining formalities in person.',
  'Research intern (IIT lab): requires CV, transcripts, two references. Selection by faculty committee interview. No fees. Stipend per institute norms. Contact via institute email domain only.',
];
// ---- Legit texts PAIRED with matching URLs (avoids artificial brand mismatch) ----
const legitPairs = [
  ['https://www.infosys.com/careers/', 'Infosys is hiring a Senior React Developer in Bengaluru. Requirements: 4+ years experience, TypeScript, system design. Process: online assessment, two technical interviews, HR round. Apply only via infosys.com/careers. We never ask for fees, OTPs or bank details during application. Contact: careers@infosys.com.'],
  ['https://www.upsc.gov.in/', 'Union Public Service Commission: Civil Services Examination 2026 notification. Eligibility, syllabus and schedule per official notice. Apply at upsconline.nic.in before closing date. Fee payable only through the official portal. See upsc.gov.in.'],
  ['https://www.tatamotors.com/careers', 'Tata Motors apprenticeship program: 12th pass/ITI eligible. Stipend as per Apprentices Act. Selection via written test and interview at plant. Apply through the official careers page. No charges at any stage; documents verified in person at joining.'],
  ['https://www.hdfcbank.com/careers', 'HDFC Bank hiring Probationary Officers through official recruitment. Eligibility: graduate with 50%. Selection: online test + interview. Application only on hdfcbank.com/careers. Bank never asks for OTP, CVV or netbanking passwords.'],
  ['https://sbi.co.in/careers', 'State Bank of India Specialist Officers recruitment. Vacancy circular on sbi.co.in/careers with reference number. Fee via official payment gateway only. Interviews at designated centres; original documents verified in person after provisional selection.'],
  ['https://www.cognizant.com/careers', 'Cognizant campus drive for 2024/2025 graduates: registration through college placement cell, followed by aptitude test and interviews. Offer letters issued only on company letterhead and verifiable via the candidate portal. No fees.'],
  ['https://www.tcs.com/careers', 'TCS Ninja hiring for freshers: registration on the official portal, online test, technical and managerial interviews. No fees at any stage. Contact: careers@tcs.com.'],
  ['https://ssc.gov.in/', 'Hindi: SSC GD Constable भर्ती — आधिकारिक नोटिस ssc.gov.in पर देखें। आवेदन केवल आधिकारिक पोर्टल से, फीस भी वहीं। दस्तावेज़ DV राउंड में मूल रूप में देखे जाते हैं; OTP/पिन कभी नहीं मांगा जाता।'],
  ['https://www.accenture.com/careers', 'Accenture Associate Software Engineer: BE/BTech 2025 batch, selection via cognitive + coding assessment and interviews. Apply on accenture.com. We never request bank details or payments from candidates.'],
  ['https://www.naukri.com/', 'Naukri.com job posting by verified recruiter with company profile, official email domain and interview venue. Salary range stated with experience criteria. Candidates advised to verify via employer website before sharing documents.'],
  ['https://www.infosys.com/careers/', 'Junior Accounts Assistant needed in Pune. Walk-in interview Saturday 10am-2pm at registered office address with resume and originals for verification. No advance payment; salary via bank transfer after joining formalities in person. About the company: registered office Pune, founded 2009.'],
  ['https://www.linkedin.com/jobs/', 'Research intern (university lab): requires CV, transcripts, two references. Selection by faculty committee interview. No fees. Stipend per institute norms. Contact via institute email domain only.'],
];
// technically suspicious but legitimate: plain-http / new-domain small portals with genuine content
const suspLegitPairs = [
  ['http://small-consultancy-jobs.xyz/openings/list?ref=consult2024', 'Junior telecaller required in Nagpur for a registered consultancy (established 2016, office address given). Walk-in interview with resume. Salary Rs 14000-18000. No advance, no documents over WhatsApp.'],
  ['https://startup-hiring-blr-2026.live/roles/backend-dev', 'Early-stage startup hiring backend developer (2+ yrs, Node.js). Process: take-home task + two interviews with founders. Apply via the site form (name, email, GitHub link only). No fees. Founders on LinkedIn.'],
  ['http://local-jobs-jaipur-2026.top/vacancies?page=2', 'Delivery executives needed in Jaipur. Weekly payouts, no joining charge. Meet at the hub office with Aadhaar for in-person verification only — nothing collected online.'],
  ['https://ngo-volunteers-maha-2026.live/join', 'NGO volunteer coordinator (Pune): apply with name and email only. In-person orientation. No money, no documents requested online. Registered trust, registration number published.'],
];
for (let i = 0; i < 50; i++) {
  if (i < 30) {
    const [u, t] = legitPairs[i % legitPairs.length];
    add('legit', 'standard', u, `${t} (Advt ${2000 + i})`, /Hindi|भर्ती/.test(t) ? 'hi' : 'en');
  } else {
    const [u, t] = suspLegitPairs[(i - 30) % suspLegitPairs.length];
    add('legit', 'susp-legit', u, `${t} (Advt ${2000 + i})`, 'en');
  }
}

writeFileSync(join(dir, 'dataset.json'), JSON.stringify({ version: '1.0.0', count: rows.length, rows }, null, 1));
console.log(`wrote dataset.json with ${rows.length} rows (${rows.filter(r=>r.label==='fraud').length} fraud, ${rows.filter(r=>r.label==='legit').length} legit)`);
