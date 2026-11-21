import { NextRequest, NextResponse } from 'next/server';
const ALLOWED = new Set(['register', 'login', 'totp/verify', 'email/verify', 'email/resend']);
export async function POST(request: NextRequest, context: { params: Promise<{ path: string[] }> }) {
 const { path } = await context.params;
 const endpoint = path.join('/');
 if (!ALLOWED.has(endpoint)) return NextResponse.json({message:'Not found.'},{status:404});
 const origin = request.headers.get('origin');
 if (!origin || origin !== request.nextUrl.origin) return NextResponse.json({message:'Origin not allowed.'},{status:403});
 if (!(request.headers.get('content-type') || '').toLowerCase().startsWith('application/json')) return NextResponse.json({message:'JSON required.'},{status:415});
 const body = await request.text();
 if (new TextEncoder().encode(body).length > 8192) return NextResponse.json({message:'Request too large.'},{status:413});
 const backend = process.env.ZEROID_API_URL;
 if (!backend) return NextResponse.json({message:'Identity service is not configured.'},{status:503});
 try {
  const url = new URL(`/api/${endpoint}`, backend);
  const headers = new Headers({ 'Content-Type': 'application/json', 'Accept': 'application/json' });
  const cookies = request.headers.get('cookie'); if (cookies) headers.set('Cookie', cookies);
  const abort = AbortSignal.timeout(10000);
  const upstream = await fetch(url, {method:'POST',headers,body,cache:'no-store',signal:abort,redirect:'manual'});
  const contentType = upstream.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) return NextResponse.json({message:'Unexpected identity service response.'},{status:502});
  const text = (await upstream.text()).slice(0,8192);
  const response = new NextResponse(text, {status:upstream.status,headers:{'Content-Type':'application/json','Cache-Control':'no-store'}});
  for (const cookie of upstream.headers.getSetCookie()) response.headers.append('Set-Cookie', cookie);
  return response;
 } catch { return NextResponse.json({message:'Identity service unavailable.'},{status:502}); }
}
