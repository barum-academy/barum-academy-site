/**
 * 바름국어과학학원 — 상담 신청 문자(SMS) 알림
 *
 * Netlify Forms 가 상담 신청을 "정상 접수(verified)"한 뒤에만 Netlify 가 이 함수를 실행합니다.
 * (스팸으로 분류된 신청에는 실행되지 않음)  신청 데이터 저장·이메일 알림은 Netlify 가 먼저 처리하므로,
 * 이 함수에서 문자 발송이 실패해도 신청 데이터와 이메일 알림에는 영향이 없습니다.
 *
 * 필요한 Netlify 환경변수 (홈페이지 소스에는 넣지 않습니다)
 *   SMS_ENABLED        "true" 일 때만 발송
 *   SOLAPI_API_KEY     솔라피 API Key
 *   SOLAPI_API_SECRET  솔라피 API Secret
 *   SMS_FROM           솔라피에 등록·인증한 발신번호 (예: 01099749944)
 *   SMS_TO             알림 받을 관리자 번호 (예: 01099749944)
 *   NETLIFY_API_TOKEN  (선택) 중복 신청 확인용 Netlify 개인 액세스 토큰
 *
 * 외부 라이브러리를 쓰지 않습니다(Node 기본 기능만 사용).
 * 로그에는 이름·연락처를 남기지 않고 신청번호와 결과만 남깁니다.
 */
import crypto from "node:crypto";

const sentRecently = new Set();               // 같은 실행 환경 안에서의 중복 방지
const digits = v => String(v || "").replace(/\D/g, "");
const log = (obj) => console.log(JSON.stringify({ tag: "barum-sms", at: new Date().toISOString(), ...obj }));

function kstTime(iso) {   // 예: 10/29 14:05 (한국 시간)
  const d = iso ? new Date(iso) : new Date();
  const k = new Date(d.getTime() + 9 * 3600 * 1000);
  const z = n => String(n).padStart(2, "0");
  return `${z(k.getUTCMonth() + 1)}/${z(k.getUTCDate())} ${z(k.getUTCHours())}:${z(k.getUTCMinutes())}`;
}

function solapiAuth(apiKey, apiSecret) {
  const date = new Date().toISOString();
  const salt = crypto.randomBytes(16).toString("hex");
  const signature = crypto.createHmac("sha256", apiSecret).update(date + salt).digest("hex");
  return `HMAC-SHA256 apiKey=${apiKey}, date=${date}, salt=${salt}, signature=${signature}`;
}

/* (선택) 같은 신청번호로 먼저 접수된 신청이 있으면 문자를 다시 보내지 않음 */
async function isDuplicate(payload, requestId) {
  const token = process.env.NETLIFY_API_TOKEN;
  if (!token || !payload.form_id || !requestId) return false;
  try {
    const res = await fetch(`https://api.netlify.com/api/v1/forms/${payload.form_id}/submissions?per_page=100`,
      { headers: { Authorization: `Bearer ${token}` } });
    if (!res.ok) return false;
    const list = await res.json();
    return list.some(s => s.id !== payload.id && s.data && s.data.requestId === requestId
      && (s.created_at || "") < (payload.created_at || "9999"));
  } catch { return false; }
}

export default async (req) => {
  let body = {};
  try { body = await req.json(); } catch { log({ result: "skip", reason: "invalid-body" }); return new Response("ok"); }
  const p = body.payload || {};
  const d = p.data || {};
  const formName = p.form_name || d["form-name"];
  const requestId = String(d.requestId || "");
  const rid = requestId.replace(/-/g, "").slice(0, 8) || String(p.id || "").slice(0, 8);
  const mode = d.mode === "테스트" ? "테스트" : "실제";

  try {
    if (formName !== "consult") { log({ rid, result: "skip", reason: "other-form" }); return new Response("ok"); }
    if (d.website) { log({ rid, result: "skip", reason: "honeypot" }); return new Response("ok"); }
    if (process.env.SMS_ENABLED !== "true") { log({ rid, mode, result: "skip", reason: "SMS_ENABLED-not-true" }); return new Response("ok"); }

    const { SOLAPI_API_KEY: key, SOLAPI_API_SECRET: secret } = process.env;
    const from = digits(process.env.SMS_FROM), to = digits(process.env.SMS_TO);
    if (!key || !secret || !from || !to) { log({ rid, mode, result: "fail", reason: "missing-env" }); return new Response("ok"); }

    const dedupeKey = requestId || p.id;
    if (sentRecently.has(dedupeKey) || await isDuplicate(p, requestId)) {
      log({ rid, mode, result: "skip", reason: "duplicate" }); return new Response("ok");
    }

    // 최소 정보만: 접수 사실, 학생 이름, 학부모 연락처, 신청 일시, 신청번호 (상담 내용은 넣지 않음)
    const name = String(d.name || "").trim().slice(0, 20);
    const phone = String(d.phone || "").trim().slice(0, 13);
    const text = `[바름]상담신청${mode === "테스트" ? "(테스트)" : ""} #${rid}\n${name} ${phone}\n${kstTime(p.created_at)} 접수`;

    const res = await fetch("https://api.solapi.com/messages/v4/send-many/detail", {
      method: "POST",
      headers: { Authorization: solapiAuth(key, secret), "Content-Type": "application/json" },
      body: JSON.stringify({ messages: [{ to, from, text }] }),
    });
    const out = await res.json().catch(() => ({}));
    const failed = Array.isArray(out.failedMessageList) && out.failedMessageList.length > 0;
    if (res.ok && !failed) {
      sentRecently.add(dedupeKey);
      log({ rid, mode, result: "sent", http: res.status, groupId: out.groupInfo && out.groupInfo._id });
    } else {
      log({ rid, mode, result: "fail", http: res.status, error: out.errorCode || (failed && out.failedMessageList[0].statusCode) || "unknown",
            message: String(out.errorMessage || (failed && out.failedMessageList[0].statusMessage) || "").slice(0, 120) });
    }
  } catch (e) {
    log({ rid, mode, result: "fail", reason: "exception", message: String(e && e.message).slice(0, 120) });
  }
  return new Response("ok");   // 항상 성공 응답: 문자 실패가 신청 처리에 영향을 주지 않음
};
