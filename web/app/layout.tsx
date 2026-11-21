import type { Metadata } from 'next';
import './style.css';
export const metadata: Metadata = { title: 'ZeroID · Secure Identity', description: 'ZeroID identity verification forms' };
export default function Layout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <html lang="en"><body><header className="top"><a href="/" className="brand">◈ ZeroID</a><span className="tag">by ZeroT</span></header><main>{children}</main><footer>Secure authentication · CSC 327</footer></body></html>;
}
