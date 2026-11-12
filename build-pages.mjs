import { writeFileSync } from 'node:fs';

const anonKey = process.env.SUPABASE_ANON_KEY;
if (!anonKey) throw new Error('Set SUPABASE_ANON_KEY in Cloudflare Pages environment variables');

const supabaseUrl = 'https://cfaowiuefyrmpksavenh.supabase.co';
writeFileSync('public/config.js', `window.SOKUHO_CONFIG = ${JSON.stringify({
  apiBaseUrl: `${supabaseUrl}/functions/v1/api`,
  anonKey,
})};\n`);
writeFileSync('public/_redirects', '/* /index.html 200\n');
