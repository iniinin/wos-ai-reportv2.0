#!/usr/bin/env node
// Node.js 18+. No third-party packages; no network requests.
import { readFile, open, mkdir } from 'node:fs/promises';
import { resolve, dirname } from 'node:path';
import { pbkdf2Sync, createDecipheriv } from 'node:crypto';
import { createInterface } from 'node:readline/promises';
import { Writable } from 'node:stream';
import { fileURLToPath } from 'node:url';

export async function readPasswordFile(path) {
  const bytes = await readFile(path);
  let end = bytes.length;
  if (end && bytes[end - 1] === 10) {
    end -= 1;
    if (end && bytes[end - 1] === 13) end -= 1;
  }
  const password = Buffer.from(bytes.subarray(0, end));
  bytes.fill(0);
  if (!password.length || password.includes(10) || password.includes(13)) {
    password.fill(0);
    throw new Error('密码文件须包含一行非空密码。');
  }
  return password;
}

function decodeBase64(value) {
  if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error('密文格式不正确。');
  const result = Buffer.from(value, 'base64');
  if (result.toString('base64') !== value) throw new Error('密文格式不正确。');
  return result;
}

export function decryptPayload(payload, password) {
  if (!payload || payload.format !== 'local-notes-vault-v1' || payload.cipher !== 'AES-GCM' || payload.keyBits !== 256 || payload.tagBits !== 128 || payload.kdf !== 'PBKDF2' || payload.hash !== 'SHA-256' || payload.iterations !== 600000 || payload.additionalData !== 'local-notes-vault-v1') throw new Error('不支持的密文格式或加密参数。');
  const salt = decodeBase64(payload.salt);
  const iv = decodeBase64(payload.iv);
  const combined = decodeBase64(payload.ciphertext);
  if (salt.length !== 16 || iv.length !== 12 || combined.length < 17) throw new Error('密文格式不正确。');
  const key = pbkdf2Sync(password, salt, payload.iterations, 32, 'sha256');
  let firstPart = null;
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv, {authTagLength:16});
    decipher.setAAD(Buffer.from(payload.additionalData, 'utf8'));
    decipher.setAuthTag(combined.subarray(-16));
    firstPart = decipher.update(combined.subarray(0, -16));
    const finalPart = decipher.final();
    const plaintext = Buffer.concat([firstPart, finalPart]);
    finalPart.fill(0);
    return plaintext;
  } catch {
    throw new Error('无法解密：密码不正确，或文件已损坏、被修改。');
  } finally {
    key.fill(0);
    if (firstPart) firstPart.fill(0);
  }
}

async function askPassword() {
  if (!process.stdin.isTTY) throw new Error('无交互终端。请使用 --password-file 提供本机密码文件。');
  const silentOutput = new Writable({write(chunk, encoding, callback) { callback(); }});
  const rl = createInterface({input:process.stdin, output:silentOutput, terminal:true, historySize:0});
  process.stderr.write('访问密码（不显示输入）：');
  let value = '';
  try {
    value = await rl.question('');
    if (!value) throw new Error('密码不能为空。');
    return Buffer.from(value, 'utf8');
  } finally {
    value = '';
    rl.close();
    silentOutput.end();
    process.stderr.write('\n');
  }
}

async function main() {
  const args = process.argv.slice(2);
  const options = {};
  if (args.includes('--help') || args.includes('-h')) {
    process.stdout.write('用法：node decrypt.mjs [--input encrypted-notes.json] [--output ./decrypted-notes.md] [--password-file <本机密码文件>]\n省略 --password-file 时在终端静默输入密码。不支持命令行明文密码参数。输出文件已存在时拒绝覆盖。\n');
    return;
  }
  for (let i = 0; i < args.length; i += 2) {
    if (!['--input', '--output', '--password-file'].includes(args[i]) || !args[i + 1] || options[args[i]]) throw new Error('参数不正确。运行 node decrypt.mjs --help 查看用法。');
    options[args[i]] = args[i + 1];
  }
  const inputPath = resolve(options['--input'] || fileURLToPath(new URL('./encrypted-notes.json', import.meta.url)));
  const outputPath = resolve(options['--output'] || './decrypted-notes.md');
  const passwordPath = options['--password-file'] && resolve(options['--password-file']);
  if (outputPath === inputPath || outputPath === passwordPath) throw new Error('输出不能覆盖密文或密码文件。');
  let password = null;
  let plaintext = null;
  let file = null;
  try {
    const payload = JSON.parse(await readFile(inputPath, 'utf8'));
    password = passwordPath ? await readPasswordFile(passwordPath) : await askPassword();
    plaintext = decryptPayload(payload, password);
    await mkdir(dirname(outputPath), {recursive:true, mode:0o700});
    // Exclusive creation prevents accidental overwrite and symlink replacement.
    file = await open(outputPath, 'wx', 0o600);
    await file.writeFile(plaintext);
    await file.close();
    file = null;
    process.stdout.write('已解密到新建的本地 Markdown 文件。此文件是明文，请勿上传公开仓库。\n');
  } catch (error) {
    if (error.code === 'EEXIST') throw new Error('输出文件已存在，未覆盖。请更换 --output 路径。');
    if (error instanceof SyntaxError) throw new Error('JSON 密文文件格式不正确。');
    throw error;
  } finally {
    if (file) await file.close();
    if (password) password.fill(0);
    if (plaintext) plaintext.fill(0);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => {
    process.stderr.write(error.message + '\n');
    process.exitCode = 1;
  });
}
