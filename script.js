/**
 * AES-256-GCM Client-Side Crypto Tool
 * ES2022 / Web Crypto API
 * 
 * 厳格なクライアント完結型設計：
 * - 外部通信/API呼び出しなし
 * - localStorage / sessionStorage / Cookie保存なし
 * - コンソールへの機密ログ出力なし
 */

'use strict';

// ==========================================================================
// ユーティリティ & 暗号化コアモジュール
// ==========================================================================

const CryptoService = {
  FORMAT_PREFIX: 'AESGCM:v1:',
  IV_LENGTH_BYTES: 12, // 96 bits (AES-GCM 推奨値)

  /**
   * Uint8Array を Base64 文字列に変換する（スタックオーバーフロー回避版）
   * @param {Uint8Array} uint8Array
   * @returns {string}
   */
  uint8ArrayToBase64(uint8Array) {
    let binary = '';
    const len = uint8Array.byteLength;
    const chunkSize = 0x8000; // 32KB ごとにチャンク処理
    for (let i = 0; i < len; i += chunkSize) {
      const chunk = uint8Array.subarray(i, Math.min(i + chunkSize, len));
      binary += String.fromCharCode.apply(null, chunk);
    }
    return btoa(binary);
  },

  /**
   * Base64 文字列を Uint8Array に変換する
   * @param {string} base64
   * @returns {Uint8Array}
   */
  base64ToUint8Array(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  },

  /**
   * マスターキー文字列から SHA-256 ハッシュを計算し、AES-256 CryptoKey を導出する
   * @param {string} masterKey
   * @returns {Promise<CryptoKey>}
   */
  async deriveKey(masterKey) {
    const encoder = new TextEncoder();
    const keyData = encoder.encode(masterKey);

    // SHA-256 でハッシュ化 (32バイト = 256ビット)
    const hashBuffer = await crypto.subtle.digest('SHA-256', keyData);

    // AES-GCM 用の CryptoKey としてインポート
    return await crypto.subtle.importKey(
      'raw',
      hashBuffer,
      { name: 'AES-GCM' },
      false, // キーのエクスポートは不可
      ['encrypt', 'decrypt']
    );
  },

  /**
   * 平文を AES-256-GCM で暗号化する
   * @param {string} masterKey
   * @param {string} plainText
   * @returns {Promise<string>} AESGCM:v1:<base64(iv)>:<base64(ciphertext)>
   */
  async encrypt(masterKey, plainText) {
    if (!masterKey) {
      throw new Error('Master Key is required.');
    }
    if (!plainText) {
      throw new Error('Plain Text is required.');
    }

    const key = await this.deriveKey(masterKey);

    // 12バイトのランダムIV生成
    const iv = crypto.getRandomValues(new Uint8Array(this.IV_LENGTH_BYTES));

    // UTF-8 エンコード
    const encoder = new TextEncoder();
    const encodedData = encoder.encode(plainText);

    // 暗号化 (ciphertext には末尾に 128bit の認証タグが含まれる)
    const cipherBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: iv,
        tagLength: 128
      },
      key,
      encodedData
    );

    const ivBase64 = this.uint8ArrayToBase64(iv);
    const cipherBase64 = this.uint8ArrayToBase64(new Uint8Array(cipherBuffer));

    return `${this.FORMAT_PREFIX}${ivBase64}:${cipherBase64}`;
  },

  /**
   * 暗号化文字列を解析して平文に復号する
   * @param {string} masterKey
   * @param {string} encryptedString
   * @returns {Promise<string>}
   */
  async decrypt(masterKey, encryptedString) {
    if (!masterKey) {
      throw new Error('Master Key is required.');
    }
    if (!encryptedString) {
      throw new Error('Encrypted data is required.');
    }

    const trimmed = encryptedString.trim();
    const parts = trimmed.split(':');

    // フォーマット検証: AESGCM:v1:<iv>:<ciphertext>
    if (parts.length !== 4 || parts[0] !== 'AESGCM' || parts[1] !== 'v1') {
      throw new Error('Invalid encrypted format.');
    }

    let iv, cipherBytes;
    try {
      iv = this.base64ToUint8Array(parts[2]);
      cipherBytes = this.base64ToUint8Array(parts[3]);
    } catch {
      throw new Error('Invalid encrypted format.');
    }

    // IV の長さ検証
    if (iv.byteLength !== this.IV_LENGTH_BYTES) {
      throw new Error('Invalid encrypted format.');
    }

    const key = await this.deriveKey(masterKey);

    try {
      const decryptedBuffer = await crypto.subtle.decrypt(
        {
          name: 'AES-GCM',
          iv: iv,
          tagLength: 128
        },
        key,
        cipherBytes
      );

      const decoder = new TextDecoder('utf-8', { fatal: true });
      return decoder.decode(decryptedBuffer);
    } catch {
      // 鍵の不一致または改ざん検知（認証タグ不一致）
      throw new Error('Wrong key or corrupted data.');
    }
  }
};

// ==========================================================================
// UI コントローラー
// ==========================================================================

document.addEventListener('DOMContentLoaded', () => {
  // --- DOM 要素の取得 ---
  const tabEncrypt = document.getElementById('tab-encrypt');
  const tabDecrypt = document.getElementById('tab-decrypt');
  const panelEncrypt = document.getElementById('panel-encrypt');
  const panelDecrypt = document.getElementById('panel-decrypt');

  const encryptKeyInput = document.getElementById('encrypt-key');
  const encryptPlainInput = document.getElementById('encrypt-plain');
  const encryptOutput = document.getElementById('encrypt-output');
  const btnEncrypt = document.getElementById('btn-encrypt');
  const encryptError = document.getElementById('encrypt-error');
  const btnCopyEncrypted = document.getElementById('btn-copy-encrypted');

  const decryptKeyInput = document.getElementById('decrypt-key');
  const decryptInput = document.getElementById('decrypt-input');
  const decryptOutput = document.getElementById('decrypt-output');
  const btnDecrypt = document.getElementById('btn-decrypt');
  const decryptError = document.getElementById('decrypt-error');
  const btnCopyDecrypted = document.getElementById('btn-copy-decrypted');

  const themeToggle = document.getElementById('theme-toggle');
  const sunIcon = document.getElementById('sun-icon');
  const moonIcon = document.getElementById('moon-icon');

  // --- タブ切り替え処理 ---
  function switchTab(activeTab, activePanel, inactiveTab, inactivePanel) {
    activeTab.classList.add('active');
    activeTab.setAttribute('aria-selected', 'true');
    activePanel.classList.add('active');
    activePanel.removeAttribute('hidden');

    inactiveTab.classList.remove('active');
    inactiveTab.setAttribute('aria-selected', 'false');
    inactivePanel.classList.remove('active');
    inactivePanel.setAttribute('hidden', 'true');
  }

  tabEncrypt.addEventListener('click', () => {
    switchTab(tabEncrypt, panelEncrypt, tabDecrypt, panelDecrypt);
  });

  tabDecrypt.addEventListener('click', () => {
    switchTab(tabDecrypt, panelDecrypt, tabEncrypt, panelEncrypt);
  });

  // --- パスワード表示 / 非表示トグル ---
  document.querySelectorAll('.btn-toggle-visibility').forEach((button) => {
    button.addEventListener('click', () => {
      const targetId = button.getAttribute('data-target');
      const input = document.getElementById(targetId);
      if (!input) return;

      if (input.type === 'password') {
        input.type = 'text';
        button.textContent = 'Hide';
      } else {
        input.type = 'password';
        button.textContent = 'Show';
      }
    });
  });

  // --- エラー表示ヘルパー ---
  function showError(element, message) {
    element.textContent = message;
    element.removeAttribute('hidden');
  }

  function clearError(element) {
    element.textContent = '';
    element.setAttribute('hidden', 'true');
  }

  // --- コピー機能ヘルパー ---
  async function handleCopy(button, targetElement) {
    const text = targetElement.value;
    if (!text) return;

    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        await navigator.clipboard.writeText(text);
      } else {
        targetElement.select();
        document.execCommand('copy');
      }

      const originalText = button.textContent;
      button.textContent = 'Copied!';
      button.classList.add('copied');
      button.disabled = true;

      setTimeout(() => {
        button.textContent = originalText;
        button.classList.remove('copied');
        button.disabled = false;
      }, 2000);
    } catch {
      alert('クリップボードへのコピーに失敗しました。手動でコピーしてください。');
    }
  }

  btnCopyEncrypted.addEventListener('click', () => handleCopy(btnCopyEncrypted, encryptOutput));
  btnCopyDecrypted.addEventListener('click', () => handleCopy(btnCopyDecrypted, decryptOutput));

  // --- 暗号化実行 ---
  btnEncrypt.addEventListener('click', async () => {
    clearError(encryptError);
    encryptOutput.value = '';
    btnCopyEncrypted.disabled = true;

    const masterKey = encryptKeyInput.value;
    const plainText = encryptPlainInput.value;

    try {
      const encryptedString = await CryptoService.encrypt(masterKey, plainText);
      encryptOutput.value = encryptedString;
      btnCopyEncrypted.disabled = false;
    } catch (err) {
      showError(encryptError, err.message || 'Encryption failed.');
    }
  });

  // --- 復号実行 ---
  btnDecrypt.addEventListener('click', async () => {
    clearError(decryptError);
    decryptOutput.value = '';
    btnCopyDecrypted.disabled = true;

    const masterKey = decryptKeyInput.value;
    const encryptedData = decryptInput.value;

    try {
      const decryptedText = await CryptoService.decrypt(masterKey, encryptedData);
      decryptOutput.value = decryptedText;
      btnCopyDecrypted.disabled = false;
    } catch (err) {
      showError(decryptError, err.message || 'Decryption failed.');
    }
  });

  // --- テーマ制御（OS設定検知 & 手動切り替え） ---
  function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    if (theme === 'dark') {
      sunIcon.style.display = 'block';
      moonIcon.style.display = 'none';
    } else {
      sunIcon.style.display = 'none';
      moonIcon.style.display = 'block';
    }
  }

  // 初期テーマ判定 (prefers-color-scheme)
  const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)');
  let currentTheme = systemPrefersDark.matches ? 'dark' : 'light';
  applyTheme(currentTheme);

  // OSテーマ変更検知
  systemPrefersDark.addEventListener('change', (e) => {
    currentTheme = e.matches ? 'dark' : 'light';
    applyTheme(currentTheme);
  });

  // ボタンによる手動切り替え（セッション限りのみ、ストレージ不使用）
  themeToggle.addEventListener('click', () => {
    currentTheme = currentTheme === 'dark' ? 'light' : 'dark';
    applyTheme(currentTheme);
  });
});