#!/usr/bin/env python3
"""A safety net for Claude Code memory notes: masks passwords and tokens with [REDACTED].

Registered as two Claude Code hooks (see README.md):

  prompt  (UserPromptSubmit)  If the user's message contains something that looks like a
          secret, stores only its HMAC-SHA256 fingerprint, never the text. Then reviews the
          notes that have changed.
  memory  (PostToolUse)       Reviews the note that a tool has just written, or every changed
          note after a shell command.

A review replaces, in Markdown files inside the memory folders only:

  1. any secret the user has given before, found by fingerprint;
  2. tokens with a recognisable format (GitHub, Anthropic, OpenAI, AWS, PEM blocks...);
  3. "password: X" style labels with a value that looks like a secret, in 15 languages;
  4. the password in URLs such as scheme://user:X@host.

By hand:

  claudepassredactor.py scan [--context] [--all]   list what would be replaced, never showing values
  claudepassredactor.py redact [--all]             review every note now
  claudepassredactor.py status                     folders, key and fingerprint health, hook paths
  claudepassredactor.py add | forget               register or drop a secret, typed at a hidden prompt
  claudepassredactor.py reset --yes                delete the key and this computer's fingerprints

This is a safety net, not a vault: see "What it does not guarantee" in the README.
Python standard library only.
"""
from __future__ import annotations

import functools
import hmac
import json
import os
import re
import secrets
import stat
import sys
import time
import unicodedata

__version__ = "1.0.0"

TAG = "[REDACTED]"
KEY_BYTES = 32
MAX_VALUE = 8192                       # longest value treated as one secret, in characters
MAX_NOTE_BYTES = 4 * 1024 * 1024       # larger notes are reported, not read
HOOK_BUDGET = 10.0                     # seconds a hook may spend reviewing; hooks have a timeout
LOCK_TIMEOUT = 12.0                    # longer than a review, so waiting is normally enough
LOG_MAX_BYTES = 256 * 1024
REPLACE_DELAYS = (0.05, 0.1, 0.2, 0.4, 0.8)   # a scanner or editor may briefly hold the file
STORE_VERSION = 1
_PENDING_PREFIX = "fingerprints.pending-"

# Scripts written without spaces between words, plus their punctuation. A value stops here,
# and a neighbouring character from these ranges counts as a word edge.
_NO_SPACE = "\u0E00-\u0E7F\u3000-\u30FF\u3400-\u4DBF\u4E00-\u9FFF\uAC00-\uD7AF\uFF00-\uFFEF"


# --- what counts as a secret ---------------------------------------------------------------

_NOT_VALUES = frozenset("""
    incorrect wrong invalid required optional expired correct valid empty none null nil true
    false undefined unknown hidden secret password passwd passphrase passcode token pass
    changeme example placeholder default strong weak temporary mandatory same
    incorrecta incorrecto correcta correcto nueva nuevo vieja viejo antigua antiguo igual misma
    mismo otra segura seguro larga corta ninguna nada valida válida caducada temporal maestra
    siempre distinta buena mala esta aquella tuya mía suya requerida obligatoria contraseña
    errada inválida obrigatória nova antiga mesma forte fraca senha expirada
    incorrecte erroné erronée invalide requis requise obligatoire nouveau nouvelle ancien
    ancienne même expiré expirée
    falsch ungültig erforderlich richtig neue alte abgelaufen leer passwort kennwort
    errata sbagliata corretta obbligatoria nuova vecchia stessa scaduta
    onjuist fout ongeldig verplicht nieuw verlopen juist wachtwoord
    nieprawidłowe nieprawidłowy błędne wymagane nowe stare ważne puste hasło
    неверный неправильный обязательный новый старый верный пустой пароль
    неправильний невірний обовязковий новий старий порожній
    错误的 不正确 正确的 必须的 間違い 必須です 필수입니다 잘못됨 ถูกต้อง จำเป็น गलत सही आवश्यक
""".split())

_NOT_SECRET = re.compile(
    r"""
      ^\$\{ | ^\$\( | ^\$(?-i:[A-Z_][A-Z0-9_]*)$ | ^\$[a-z_]+$ | ^\$env: | ^%\w+%$ | ^%[sd]$
    | ^\{+[^{}]*\}*$ | ^<[^>]*>?$ | ^\[[^\]]*\]?$ | ^\(
    | ^(?-i:[a-z_][a-z0-9_.]{2,})\(                # a function call
    | ^(?:process\.env|os\.environ|os\.getenv|env|secrets|vars|config|settings|self|this)[.\[]
    | ^\*+$ | ^x{3,}$ | ^[•·●∙◦.\-_\#]+$ | …
    | ^[a-z]:[\\/] | ^\\\\ | ^(?:~|\.{0,2})/        # paths
    | \.(?:ps1|txt|md|pem|json|py|sh|xml|cfg|key|env|ya?ml|toml|ini|conf|log|kdbx|gpg|asc|bat
          |cmd|exe|dll|js|ts|csv|db|sqlite)$        # file names
    | ^[a-z][a-z0-9+.\-]*:// | ^https?:             # URLs
    | ^v?\d+(?:\.\d+){1,3}(?:[-+][\w.\-]+)?$        # versions
    | ^\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?$            # IPv4
    | ^[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}$        # IPv6
    | ^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}(?:[T\ ]\S*)?$  # dates and times
    | ^\d{1,2}[-/.]\d{1,2}[-/.]\d{2,4}$
    | ^\d{1,2}:\d{2}(?::\d{2})?$
    | ^\d+(?:[.,]\d+)?(?:chars?|characters?|digits?|letters?|bytes?|bits?|[kmgt]i?b|px|ms|secs?
          |mins?|h|hrs?|days?|rpm|[kmg]?hz|%|x)$    # quantities
    | ^[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+$             # e-mail addresses
    | ^\d+-\d+$                                     # ranges
    | ^[^\W\d_]+\]                                  # syntax in documents: [user[:password]@]host
    | ^[^\W\d_]*pass(?:word|wd)[^\W\d_]*$           # mypassword, newpassword
    | ^\$\w+(?:->|\.|\[)                            # $request->password
    | ^(?-i:[A-Z]+)\(\d+\)?$                        # VARCHAR(255)
    | ^(?-i:[A-Z]{2,}(?:_[A-Z]{2,})+)$              # names of environment variables
    | ^(?:[a-z0-9]+[+/])?utf-?(?:8|16|32)$          # text encodings: NFC+UTF-8
    | redact                                        # our own tag and similar ones
    | placeholder | ^change[-_]?me$ | ^(?:your|example|sample|dummy)[-_.]
    """,
    re.IGNORECASE | re.VERBOSE)
_NO_SPACE_TEXT = re.compile(f"[{_NO_SPACE}]")

_CHECKED = 256                         # the start of a very long value says enough, and quickly
_TWO_WORDS = re.compile(r"[^\W\d_]+['’/.-][^\W\d_]+\Z")   # well-known, d'origine, read/write, user.name
_SNAKE_CASE = re.compile(r"[a-z]+(?:_[a-z]+)+\Z")          # resize_images: a name in code


def nfc(text):
    return text if text.isascii() else unicodedata.normalize("NFC", text)


def _char_kinds(value):
    """Kinds of character: l letter, U capital other than the first, d digit, s symbol."""
    kinds = set()
    for i, ch in enumerate(value):
        category = unicodedata.category(ch)
        if category[0] in "LM":          # marks count as letters: Hindi and Thai words need them
            kinds.add("l")
            if i and ch.isupper():
                kinds.add("U")
        elif category == "Nd":
            kinds.add("d")
        else:
            kinds.add("s")
    return kinds


@functools.lru_cache(maxsize=1024)
def classify(value, quoted=False):
    """'strong' (replace anywhere), 'weak' (only next to a keyword) or None (not a secret)."""
    if not 4 <= len(value) <= MAX_VALUE or value.lower() in _NOT_VALUES or _NOT_SECRET.search(value[:_CHECKED]):
        return None
    kinds = _char_kinds(value[:_CHECKED])
    if kinds <= {"l", "U"}:              # only letters: could be any word
        if quoted and not _NO_SPACE_TEXT.search(value):  # 「...」 often just marks a phrase
            return "strong" if len(value) >= 8 else "weak"
        return "weak" if "U" in kinds else None
    if _TWO_WORDS.match(value) or _SNAKE_CASE.match(value):
        return "weak" if quoted else None
    if len(value) >= 8 and len(kinds - {"U"}) >= 2:
        return "strong"
    return "weak"


def _accept(value, quoted, tier):
    """Apply what the keyword allows. pin: digits only. Technical terms: strong, or long digits.
    Ambiguous everyday words: strong, with a digit."""
    if tier == "pin":
        return "weak" if value.isdigit() and 4 <= len(value) <= 12 else None
    verdict = classify(value, quoted)
    if tier == "tech":
        return verdict if verdict == "strong" or (verdict and value.isdigit() and len(value) >= 8) else None
    if tier == "credential":
        return verdict if _strong_with_digit(value, verdict) else None
    return verdict


def _strong_with_digit(value, verdict):
    kinds = _char_kinds(value[:_CHECKED])
    return verdict == "strong" and "d" in kinds and "l" in kinds


def _worth_redacting(value, verdict):
    """A label with no earlier fingerprint: strong values, or long all-digit passwords."""
    return verdict == "strong" or (verdict == "weak" and value.isdigit() and len(value) >= 8)


# --- languages -----------------------------------------------------------------------------
#
# password    words that can only mean a password: any plausible value is accepted.
# pin         PIN words: only 4 to 12 digits are accepted.
# tech        technical terms (api_key...): strong values only, in prompts and in notes.
# credential  ambiguous everyday words (key, token, secret...): strong values only, and only
#             in the user's own message, never when reviewing notes.
# hard        words between the keyword and the value, as in "the password IS x".
# soft        weaker links, as in "changed the password TO x": used last, strong values only, and
#             only if a word from `change` is in the sentence: "the password TO the-server-01"
#             names a server, not a password.
# glued       compounds that may have any prefix: German "Routerpasswort".
# spaced      the language separates words with spaces; otherwise max_gap limits the distance
#             between the keyword and its link.

_LANGS = {
    "en": dict(
        password=[r"pass(?:word|phrase|code)s?", r"passwd", r"pwd",
                  r"(?-i:[A-Z][A-Z0-9]*(?:PASSWORD|PASSWD|PWD))"],
        pin=[r"pin(?:[ -]?(?:code|number))?"],
        tech=[r"(?:api|secret|access|private|signing|encryption|license)[ _-]?keys?",
              r"secret[ _-]?access[ _-]?keys?",
              r"(?:api|auth|access|refresh|session|bearer|id)[ _-]?tokens?",
              r"(?:client|app|webhook|shared)[ _-]?secrets?",
              r"pass(?=[ \t]*[:=])",     # an everyday word: only as a clear label
              r"(?-i:[A-Z][A-Z0-9_]*_(?:PASS|TOKEN|SECRET))",
              r"(?-i:PASSWORD(?:_[A-Z0-9]+)+)"],
        credential=[r"tokens?", r"secrets?"],
        hard=r"is|was|are|were|will be|would be|should be|becomes", soft=r"to",
        change=r"set|sets|setting|change[ds]?|changing|reset|resets|update[ds]?|updating|rotate[ds]?"),
    "es": dict(
        password=[r"contrase(?:ñ|n)as?", r"claves? de acceso", r"password", r"passwd", r"pwd"],
        pin=[r"c[oó]digos? pin", r"c[oó]digos? de (?:acceso|seguridad)", r"pin"],
        credential=[r"claves?(?: secretas?)?", r"tokens?", r"secretos?"],
        hard=r"es|era|son|ser[aá]|ser[ií]a|sea|pon|usa", soft=r"a|por",
        change=r"cambi\w*|puse|pongo|actualic\w*|actualiz\w*|restablec\w*"),
    "pt": dict(
        password=[r"senhas?", r"palavras?[- ]passe", r"password"],
        pin=[r"c[oó]digos? pin", r"c[oó]digos? de (?:acesso|seguran[çc]a)", r"pin"],
        credential=[r"chaves?", r"tokens?", r"segredos?"],
        hard=r"é|era|são|ser[aá]|seja|fica", soft=r"para",
        change=r"mud\w*|alter\w*|troc\w*|troqu\w*|redefin\w*|atualiz\w*"),
    "fr": dict(
        password=[r"mots? de passe", r"mdp", r"password"],
        pin=[r"codes? pin", r"codes? d['’]acc[eè]s", r"codes? de s[eé]curit[eé]", r"pin"],
        credential=[r"cl[eé]s?", r"jetons?", r"tokens?", r"secrets?"],
        hard=r"est|c['’]est|[eé]tait|sera|serait|soit", soft=r"[aà]|en",
        change=r"chang\w*|modifi\w*|mis|mets|r[eé]initialis\w*"),
    "de": dict(
        password=[r"password", r"pwd"],
        glued=[r"(?:pass|kenn)w(?:ort(?:e?s|e)?|[oö]rter(?:n)?)"],
        pin=[r"pin(?:[- ]?(?:code|nummer))?", r"geheimzahl", r"zugangscode", r"sicherheitscode"],
        credential=[r"schl[uü]ssel", r"tokens?", r"geheimnis"],
        hard=r"ist|war|lautet|hei(?:ß|ss)t|sei|bleibt|wird", soft=r"auf|zu",
        change=r"ge[aä]ndert|[aä]nder\w*|gesetzt|setze\w*|gewechselt|wechsl\w*"),
    "it": dict(
        password=[r"password", r"passwd", r"pwd", r"parol[ae] d['’]ordine"],
        pin=[r"codice pin", r"codic[ei] di (?:accesso|sicurezza)", r"pin"],
        credential=[r"chiav[ei]", r"token", r"segreto"],
        hard=r"è|é|era|sar[aà]|sia", soft=r"a|in",
        change=r"cambi\w*|modific\w*|impost\w*|aggiorn\w*"),
    "nl": dict(
        password=[r"password"],
        glued=[r"wachtwoord(?:en)?"],
        pin=[r"pin(?:code)?", r"toegangscode", r"beveiligingscode"],
        credential=[r"sleutels?", r"tokens?", r"geheim"],
        hard=r"is|was|wordt|luidt|blijft", soft=r"naar|in",
        change=r"gewijzigd|wijzig\w*|veranderd|verander\w*|ingesteld|aangepast"),
    "pl": dict(
        password=[r"has[łl](?:o|a|u|em)", r"ha[śs]le", r"has(?:eł|el)"],
        pin=[r"kod(?:u|em)? pin", r"kod(?:u|em)? (?:dost[eę]pu|zabezpieczaj[aą]cy)", r"pin"],
        credential=[r"klucz(?:a|em)?", r"sekrety?"],     # not "token": its "to" is an English word
        hard=r"to|jest|by[łl]o|b[eę]dzie|brzmi", soft=r"na",
        change=r"zmieni\w*|ustawi\w*"),
    "ru": dict(
        script="\u0400-\u04FF",
        password=[r"парол(?:ь|я|ю|ем|е|и|ей|ям|ями|ях)", r"password"],
        pin=[r"пин(?:[- ]?код(?:а|ом)?)?", r"pin", r"код(?:а|ом)? (?:доступа|безопасности)"],
        credential=[r"ключ(?:а|ом)?", r"токен(?:а|ом)?", r"секрет(?:а|ом)?"],
        hard=r"это|был|будет|такой|равен", soft=r"на",
        change=r"смени\w*|поменя\w*|измени\w*|замени\w*|установи\w*"),
    "uk": dict(
        script="\u0400-\u04FF",
        password=[r"парол(?:ь|я|ю|ем|і|ів|ям)", r"password"],
        pin=[r"пін(?:[- ]?код(?:у|ом)?)?", r"pin", r"код(?:у|ом)? (?:доступу|безпеки)"],
        credential=[r"ключ(?:а|ем)?", r"токен(?:а|ом)?", r"секрет(?:у|ом)?"],
        hard=r"це|є|був|буде|такий", soft=r"на",
        change=r"змін\w*|поміня\w*|встанови\w*"),
    "zh-CN": dict(
        spaced=False, max_gap=6, script="\u4E00-\u9FFF",
        password=[r"密码(?!学)", r"口令", r"通行码", r"(?<![A-Za-z0-9])password(?![A-Za-z0-9_])"],
        pin=[r"(?<![A-Za-z0-9])pin(?![A-Za-z0-9_])码?", r"访问码", r"安全码"],
        credential=[r"密钥", r"秘钥", r"令牌", r"(?<![A-Za-z0-9])token(?![A-Za-z0-9_])"],
        hard=r"都是|是|为|叫|改成了?|改为|设为|设置为|设置成|换成了?"),
    "ja": dict(
        spaced=False, max_gap=6, script="\u3040-\u30FF\u4E00-\u9FFF",
        password=[r"パスワード", r"暗証番号", r"パスコード", r"合言葉", r"パスフレーズ",
                  r"(?<![A-Za-z0-9])password(?![A-Za-z0-9_])"],
        pin=[r"(?<![A-Za-z0-9])pin(?![A-Za-z0-9_])(?:コード)?", r"ピン(?:コード|番号)",
             r"アクセスコード", r"セキュリティコード"],
        credential=[r"秘密鍵", r"トークン", r"シークレット", r"(?<![A-Za-z0-9])api\s?キー",
                    r"(?<![A-Za-z0-9])token(?![A-Za-z0-9_])"],
        hard=r"は|が|を|って|も"),
    "ko": dict(
        spaced=False, max_gap=12, script="\uAC00-\uD7AF",
        password=[r"비밀번호", r"비번", r"패스워드", r"암호(?![화학])",
                  r"(?<![A-Za-z0-9])password(?![A-Za-z0-9_])"],
        pin=[r"(?<![A-Za-z0-9])pin(?![A-Za-z0-9_])(?:\s?(?:번호|코드))?", r"핀\s?(?:번호|코드)",
             r"접근\s?코드", r"보안\s?코드"],
        credential=[r"토큰", r"비밀\s?키", r"시크릿", r"(?<![A-Za-z0-9])api\s?키",
                    r"(?<![A-Za-z0-9])token(?![A-Za-z0-9_])"],
        hard=r"는|은|가|이|를|을"),
    "th": dict(
        spaced=False, max_gap=16, script="\u0E00-\u0E7F",
        password=[r"รหัสผ่าน", r"พาสเวิร์ด", r"(?<![A-Za-z0-9])password(?![A-Za-z0-9_])"],
        pin=[r"รหัส\s?(?:pin|พิน)", r"(?<![A-Za-z0-9])pin(?![A-Za-z0-9_])"],
        credential=[r"รหัสลับ", r"โทเค็น", r"คีย์", r"(?<![A-Za-z0-9])token(?![A-Za-z0-9_])"],
        hard=r"คือ|เป็น|ว่า"),
    "hi": dict(
        spaced=True, sov=True, script="\u0900-\u097F", boundary=("(?<![\u0900-\u097F])", "(?![\u0900-\u097F])"),
        password=[r"पासवर्ड", r"कूटशब्द", r"गुप्त\s?शब्द", r"(?<![A-Za-z0-9])password(?![A-Za-z0-9_])"],
        pin=[r"पिन(?:\s?कोड)?", r"(?<![A-Za-z0-9])pin(?![A-Za-z0-9_])", r"एक्सेस\s?कोड"],
        credential=[r"टोकन", r"कुंजी", r"(?<![A-Za-z0-9])token(?![A-Za-z0-9_])"],
        hard=r"है|हैं|था|होगा|यह"),
}
LANGUAGES = tuple(_LANGS)

# Phrases about passwords rather than passwords: a keyword inside one of these is ignored.
_FALSE_PHRASES = re.compile("|".join((
    # en
    r"pass(?:word|phrase|code)s?\s+(?:managers?|polic(?:y|ies)|resets?|length|fields?|strength"
    r"|requirements?|rules?|complexity|expir\w+|generators?|hash(?:es|ing)?|prompts?|dialogs?"
    r"|recovery|protected|vaults?|stores?|files?|rotation|history|authentication|auth|login)\b",
    r"(?:forgot|forgotten|recover)\s+(?:your\s+|my\s+|the\s+)?password",
    r"tokens?\s+(?:count|limit|usage|budget|length|size|expir\w+|type|name|bucket|ring)\b",
    r"(?:max|num|input|output|total)[ _]tokens?\b",
    r"secrets?\s+(?:managers?|santa|sauce|scanning|stores?|files?|names?|management)\b",
    r"pin\s+(?:\d{1,2}\b|layout|out|assignment|header|mapping)",
    # es
    r"(?:gestor|administrador|pol[ií]tica|recuperaci[oó]n|restablecimiento|longitud"
    r"|requisito)(?:es|s)?\s+de\s+(?:la\s+|las\s+)?contrase(?:ñ|n)as?",
    r"contrase(?:ñ|n)as?\s+(?:olvidada|incorrecta|caducada)s?",
    r"claves?\s+(?:primaria|for[aá]nea|p[uú]blica|ssh|gpg|de\s+(?:b[oó]veda|sol|fa))",
    r"(?:palabra|punto|idea|factor|tecla|momento)s?\s+claves?",
    # pt
    r"(?:gerenciador|gerente|gestor|pol[ií]tica|recupera[çc][ãa]o|redefini[çc][ãa]o|tamanho"
    r"|comprimento)(?:es)?\s+de\s+(?:senhas?|palavras?[- ]passe)",
    r"chaves?\s+(?:p[uú]blica|prim[aá]ria|estrangeira|ssh)",
    r"palavras?[- ]chave",
    # fr
    r"(?:gestionnaire|politique|r[eé]initialisation|longueur|oubli)s?\s+(?:de|des|du)"
    r"\s+(?:mots?\s+de\s+passe|mdp)",
    r"mots?\s+de\s+passe\s+(?:oubli[eé]|incorrect|erron[eé]|expir[eé])",
    r"cl[eé]s?\s+(?:publique|primaire|usb|[eé]trang[eè]re|ssh|de\s+vo[uû]te)",
    r"mots?[- ]cl[eé]s?",
    # de
    r"(?:pass|kenn)w(?:ort|[oö]rter)[- ]?(?:manager|richtlinien?|l[aä]nge|regeln?|anforderungen?"
    r"|verwaltung|zur[uü]cksetzung)",
    r"schl[uü]ssel\s*(?:bund|wort|frage|datei)",
    r"[öo]ffentliche[rn]?\s+schl[uü]ssel",
    # it
    r"(?:gestore|gestione|politica|recupero|reimpostazione|lunghezza)\s+(?:delle?|di|della)"
    r"\s+password",
    r"password\s+(?:errata|sbagliata|dimenticata)",
    r"chiav[ei]\s+(?:pubblic[ae]|primari[ae]|esterna|ssh|di\s+violino)",
    r"parol[ae][- ]chiave",
    # nl
    r"wachtwoord[- ]?(?:manager|beheerder|beleid|lengte|eisen|herstel)",
    r"(?:openbare|publieke|primaire)\s+sleutel",
    r"sleutel(?:woord|bos|hanger)",
    # pl
    r"(?:mened[żz]er\w*|polityk\w+|reset\w*|d[łl]ugo[śs][ćc]\w*|odzyskiwani\w+)"
    r"\s+has(?:ł|l|e)\w*",
    r"klucz\w*\s+(?:publiczn\w+|g[łl][óo]wn\w+|obc\w+|ssh|wiolinow\w+)",
    r"s[łl]owa?\s+kluczow\w+",
    # ru
    r"(?:менеджер\w*|политик\w+|сброс[аеу]?|восстановлени\w+|длин\w+|требовани\w+)"
    r"\s+парол\w+",
    r"парол\w+\s+(?:неверн\w+|неправильн\w+|должен|устарел)",
    r"ключ\w*\s+(?:публичн\w+|открыт\w+|первичн\w+|ssh|скрипичн\w+)",
    r"открыт\w+\s+ключ\w*",
    # uk
    r"(?:менеджер\w*|політик\w+|скидання|відновлення|довжин\w+|вимог\w+)\s+парол\w+",
    r"парол\w+\s+(?:неправильн\w+|невірн\w+|має\s+містити|застарів)",
    r"ключ\w*\s+(?:публічн\w+|відкрит\w+|первинн\w+|ssh|скрипков\w+)",
    r"відкрит\w+\s+ключ\w*",
    # zh-CN
    r"密码(?:管理器|管理|策略|长度|强度|重置|规则|错误)",
    r"(?:找回|重置|忘记)密码",
    r"公钥",
    # ja
    r"パスワード(?:マネージャ|管理|ポリシー|の?長さ|リセット|強度|を?忘れ)",
    r"公開鍵",
    # ko
    r"(?:비밀번호|패스워드|암호)\s*(?:관리자|관리|정책|길이|재설정|강도|찾기)",
    r"공개\s?키",
    # th
    r"(?:ตัวจัดการ|นโยบาย|ความยาว|รีเซ็ต|ตั้งค่า)\s*รหัสผ่าน",
    r"รหัสผ่าน\s*(?:ต้อง|ไม่ถูกต้อง|ผิด|หมดอายุ)",
    # hi
    r"पासवर्ड\s+(?:प्रबंधक|मैनेजर|नीति|लंबाई|रीसेट)",
)), re.IGNORECASE)

# Between a keyword and its value in any language: colon, equals, table cell, arrow, spaced dash,
# or the end of an XML tag that closes later (but not <password>@<host>, which is a template).
_SYMBOLS = r"=>|->|→|[:=：＝|]|>(?=[^<\n]*</)|(?<=\s)[-–—](?=\s)"
_AFTER_KEYWORD = " \t\u00a0\u202f\u3000:=：＝|>(/]*"
_QUOTES = {'"': '"', "'": "'", "`": "`", "«": "»", "“": "”", "‘": "’", "„": "“",
           "「": "」", "『": "』", "《": "》", "【": "】"}
_TRAILING = ".,;:)]}>([{<|»”’\"'`*~\\。，、；：）」』》】।\u200b\u200c\u200d\u200e\u200f\u2060\ufeff"
_INLINE_SPACE = " \t\u00a0\u202f\u3000*~"
_RAW_VALUE = re.compile(rf"[^\s{_NO_SPACE}।]+")
_FIELD_SEP = re.compile(r"[;&,](?=[\w.\-]+=)")      # Server=x;Password=y;Database=z
_JSON_SEP = re.compile(r",(?=[\"'{\[])")             # {"password":null,"user":"x"}
_CLOSING_TAG = re.compile(r"</[\w.:\-]+>")
_ATTACHED = re.compile(r"[\w-]\Z")                   # the name in name="x"
_EMPTY_FIELD = re.compile(r"[ \t]*[,;|]")
_CLAUSE_BREAK = re.compile(r"[,;|·，、；]")
_SENTENCE_END = re.compile(r"[.;!?](?=\s|$)|[。！？；।\n]")
_MAX_GAP_WORDS = 5
_MAX_WINDOW = 160
_MAX_QUOTED = 1024
_CHANGE_WINDOW = 100


_BORROWED = frozenset(("password", "passwd", "pwd"))    # English words used in other languages


class _Lang:
    def __init__(self, code, spec):
        self.borrowed = frozenset() if code in ("en", "it") else _BORROWED   # Italian's own word
        self.spaced = spec.get("spaced", True)
        self.max_gap = spec.get("max_gap", 0)
        self.sov = spec.get("sov", False)
        left, right = spec.get("boundary", (r"(?<![^\W_])", r"(?!\w)"))
        if not self.spaced:
            left, right = "", ""
        script = spec.get("script")
        self.script = re.compile(f"[{script}]") if script else None

        def group(name, fragments):
            return f"(?P<{name}>(?:{'|'.join(fragments)}){right})" if fragments else None

        # The left edge comes once, outside the alternatives: testing it first at every position
        # instead of once per alternative makes this several times faster.
        tiers = [group(name, spec.get(name, ())) for name in ("password", "pin", "tech", "credential")]
        pattern = left + "(?:" + "|".join(t for t in tiers if t) + ")"
        if spec.get("glued"):
            pattern += "|" + group("glued", spec["glued"])
        self.keywords = re.compile(pattern, re.IGNORECASE)
        link_end = f"{right}(?!-)" if self.spaced else ""     # "c'est" but not "c'est-à-dire"
        hard = f"{left}(?:{spec['hard']}){link_end}"
        self.hard = re.compile(f"{_SYMBOLS}|{hard}", re.IGNORECASE)
        self.soft = re.compile(f"{left}(?:{spec['soft']}){link_end}", re.IGNORECASE) if spec.get("soft") else None
        self.sov_link = re.compile(rf"\s+(?:{spec['hard']}){right}") if self.sov else None
        self.change = re.compile(f"{left}(?:{spec['change']}){right}", re.IGNORECASE) if spec.get("change") else None


_compiled = {}


def _languages():
    if not _compiled:
        _compiled.update((code, _Lang(code, spec)) for code, spec in _LANGS.items())
    return _compiled.values()


class _Value:
    __slots__ = ("start", "end", "text", "base", "quoted", "label_like", "ends_clause")

    def __init__(self, start, end, text, quoted, label_like=False, ends_clause=False):
        self.start, self.end, self.text, self.quoted = start, end, text, quoted
        self.base = text if quoted else text.rstrip("!?")     # "Hunter2!" may be either
        self.label_like = label_like     # "server-2024:" is the name of what comes next
        self.ends_clause = ends_clause   # "none," : what follows is about something else


def _closing_quote(text, pos, escaped):
    """Where the quote opened at pos closes on the same line, or -1. Inside a plain quote \\" does
    not close it; a quote opened as \\" closes only with another one."""
    close, limit = _QUOTES[text[pos]], pos + _MAX_QUOTED
    newline = text.find("\n", pos + 1, limit)
    if newline >= 0:
        limit = newline
    i = pos
    while True:
        i = text.find(close, i + 1, limit)
        if i < 0 or (text[i - 1] == "\\") == escaped:
            return i


def _read_value(text, pos):
    """The value that starts at pos, or None. Unquoted values end at a space or at text in a
    script written without spaces; quoted values with spaces inside are not treated as secrets."""
    n = len(text)
    while pos < n and text[pos] in _INLINE_SPACE:
        pos += 1
    if pos >= n or text[pos] in ",;|":   # "the password is, as always, ..."
        return None
    escaped = text[pos] == "\\" and text[pos + 1:pos + 2] in _QUOTES
    if escaped:
        pos += 1
    if text[pos] in _QUOTES:
        close = _closing_quote(text, pos, escaped)
        if close > pos:
            start, end = pos + 1, close - 1 if escaped else close
            while start < end and text[start].isspace():
                start += 1
            while end > start and text[end - 1].isspace():
                end -= 1
            value = text[start:end]
            if not value or any(c.isspace() for c in value):
                return None
            return _Value(start, end, value, True)
        pos += 1                         # an opening quote that never closes
    match = _RAW_VALUE.match(text, pos, pos + MAX_VALUE + 1)
    if not match:
        return None
    raw = match.group()
    json_end = _JSON_SEP.search(raw)
    if json_end:
        raw = raw[:json_end.start()]
    sep = _FIELD_SEP.search(raw)
    if sep and classify(raw[:sep.start()].rstrip(_TRAILING)) == "strong":   # if not, it is all one value
        raw = raw[:sep.start()]
    tag = _CLOSING_TAG.search(raw)
    if tag:
        raw = raw[:tag.start()]
    stripped = raw.rstrip(_TRAILING)
    while stripped.count("(") > stripped.count(")") and raw[len(stripped):len(stripped) + 1] == ")":
        stripped = raw[:len(stripped) + 1]       # the bracket closes inside the value: Pa(ss)
    if not stripped:
        return None
    rest = raw[len(stripped):]
    return _Value(pos, pos + len(stripped), stripped, False, rest.startswith(":"),
                  bool(json_end) or rest[:1] in (",", ";", "|"))


def _is_false_phrase(text, kw_start, kw_end):
    begin = max(text.rfind("\n", max(0, kw_start - 60), kw_start) + 1, kw_start - 60, 0)
    end = text.find("\n", kw_end, kw_end + 60)
    end = kw_end + 60 if end < 0 else end
    return any(m.start() < kw_end and m.end() > kw_start
               for m in _FALSE_PHRASES.finditer(text, begin, end))


class TooSlow(OSError):
    """The time budget of a hook ran out while reviewing one note."""


def _check_deadline(deadline, count):
    if deadline is not None and count & 0xFF == 0 and time.monotonic() > deadline:
        raise TooSlow()


def _labelled(text, notes_only=False, deadline=None):
    """Yield (value, verdict, tier) for every 'keyword ... link ... value' found in text."""
    count = 0
    false_phrases, values = {}, {}       # many languages share "password": check each place once
    for lang in _languages():
        if lang.script and not lang.script.search(text):
            continue                     # its links and most of its keywords need that script
        for kw in lang.keywords.finditer(text):
            count += 1
            _check_deadline(deadline, count)
            tier = "password" if kw.lastgroup == "glued" else kw.lastgroup
            if notes_only and tier == "credential":
                continue
            pos = kw.end()
            if text[pos:pos + 1] == "\\" and text[pos + 1:pos + 2] in _QUOTES:
                pos += 2
            elif text[pos:pos + 1] in _QUOTES:
                pos += 1
            if lang.spaced and pos < len(text) and text[pos] not in _AFTER_KEYWORD and not text[pos].isspace():
                continue                 # password-protected, password_hash...
            # A local weak link does not apply to a borrowed English word: Spanish "a" must not
            # read "the password a Server2024" as a value.
            soft = None if kw.group().lower() in lang.borrowed else lang.soft
            found = _find_link(text, pos, lang, tier, soft, values)
            if found:
                place = kw.span()
                if place not in false_phrases:
                    false_phrases[place] = _is_false_phrase(text, *place)
                if not false_phrases[place]:
                    yield found + (tier,)


def _value_at(text, pos, values):
    if pos not in values:
        values[pos] = _read_value(text, pos)
    return values[pos]


def _closes_outer_bracket(gap):
    """The keyword was inside brackets or a Markdown link that end here, so what follows is about
    something else: "(password given by the user): x", "[passwords](a.md) and [b = c]". A bracket
    right after the keyword is still the label: "[password]: x"."""
    if "](" in gap:
        return True
    depth = 0
    for i, ch in enumerate(gap):
        if ch in "([（":
            depth += 1
        elif ch in ")]）":
            if depth:
                depth -= 1
            elif gap[:i].strip(_INLINE_SPACE + "*_`"):
                return True
    return False


def _find_link(text, pos, lang, tier, soft, values):
    limit = min(len(text), pos + _MAX_WINDOW)
    stop = _SENTENCE_END.search(text, pos, limit)
    if stop:
        limit = stop.start()
    if lang.sov:                         # Hindi: "<password> <value> है"
        value = _value_at(text, pos, values)
        if value and lang.sov_link.match(text, value.end) and text[pos:value.start].strip(" \t") == "":
            verdict = _accept(value.base, value.quoted, tier)
            if verdict:
                return value, verdict
    for link in lang.hard.finditer(text, pos, limit):
        if _gap_too_big(text, pos, link.start(), lang):
            break
        symbol = not link.group()[0].isalpha()
        if link.group()[0] == "=" and _ATTACHED.search(text, pos, link.start()):
            return None                  # type="password" name="x": that = belongs to name
        gap = text[pos:link.start()]
        if _closes_outer_bracket(gap):
            break
        if "redact" in gap.lower() or (symbol and _CLAUSE_BREAK.search(gap)):
            return None                  # "password is none, host: x" in a language without "is"
        value = _value_at(text, link.end(), values)
        if value is None:
            if _EMPTY_FIELD.match(text, link.end()):
                return None
            continue
        verdict = _accept(value.base, value.quoted, tier)
        if verdict:
            return value, verdict
        # This label has a value, and it is not a secret: "password: none, host: srv-2024" or an
        # earlier [REDACTED]. What follows belongs to something else.
        if symbol or value.ends_clause or "redact" in value.text.lower():
            return None
    if soft and lang.change and lang.change.search(text, max(0, pos - _CHANGE_WINDOW), limit):
        for link in soft.finditer(text, pos, limit):
            if _gap_too_big(text, pos, link.start(), lang) or _closes_outer_bracket(text[pos:link.start()]):
                break
            value = _value_at(text, link.end(), values)
            if value and not value.label_like:
                verdict = _accept(value.base, value.quoted, tier)
                if verdict == "strong":
                    return value, verdict
    if tier == "password":               # "wifi password Hunter-2024x": no link at all
        value = _value_at(text, pos, values)
        attached = value and value.start == pos and (lang.spaced or text[pos] in "=:：＝")
        if value and not attached and not value.quoted and not text[pos:value.start].strip(_INLINE_SPACE):
            if _strong_with_digit(value.base, classify(value.base)):
                return value, "strong"
    return None


def _gap_too_big(text, start, end, lang):
    if lang.spaced:
        return len(text[start:end].split()) > _MAX_GAP_WORDS
    return end - start > lang.max_gap


# --- tokens with a recognisable format ------------------------------------------------------

# Patterns start with a literal so that the regex engine can skip ahead; the word edge in front
# of a match is checked afterwards in _format_matches, because a lookbehind here would be tested
# at every position of every note. The two with _EDGE need it there: a failed match can scan a
# whole run of text, and "sk-sk-sk-..." would then take quadratic time.
_EDGE = r"(?<![\w-])"
_PEM_NAME = r"[A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?"
_FORMATS = tuple((name, re.compile(pattern)) for name, pattern in (
    ("github", r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"),
    ("gitlab", r"glpat-[A-Za-z0-9_-]{20,}"),
    ("anthropic", r"sk-ant-[A-Za-z0-9_-]{20,}"),
    ("openai", _EDGE + r"sk-(?:proj-|svcacct-|admin-)?(?=[A-Za-z0-9_-]*\d)"
               r"(?=[A-Za-z0-9_-]*[A-Za-z0-9]{20})[A-Za-z0-9_-]{32,}"),
    ("stripe", r"(?:(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{24,})"),
    ("slack", r"xox[abeposr]-[A-Za-z0-9-]{10,}"),
    ("slack-webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"),
    ("discord-webhook", r"https://discord(?:app)?\.com/api/webhooks/\d+/[A-Za-z0-9_-]{30,}"),
    ("aws", r"(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])"),
    ("google", r"AIza[0-9A-Za-z_-]{35,}"),
    ("npm", r"npm_[A-Za-z0-9]{30,}"),
    ("pypi", r"pypi-[A-Za-z0-9_-]{40,}"),
    ("huggingface", r"hf_[A-Za-z0-9]{30,}"),
    ("sendgrid", r"SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}"),
    ("telegram", r"(?<![\d:])\d{8,10}:AA[A-Za-z0-9_-]{30,}"),
    ("digitalocean", r"do[opr]_v1_[a-f0-9]{40,}"),
    ("jwt", _EDGE + r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    ("authorization", r"(?i:authorization\s*[:=]\s*(?:bearer|basic|token)\s+)"
                      r"(?P<v>[A-Za-z0-9._~+/-]{16,}={0,2})"),
    ("bearer", r"(?i:(?<!\w)bearer\s+)(?P<v>[A-Za-z0-9._~+/-]{20,}={0,2})"),
))
_DEMO_TOKEN = re.compile(r"(.)\1{7,}|EXAMPLE|YOUR", re.IGNORECASE)
# The first form stops at the last @ before any slash, so p@ss works. The second allows a slash
# in the password, but not what is really a port and a path: https://host:8080/a?mail=b@c
_URL_PASSWORD = re.compile(r"(?<=://)[^\s:/<>?#\[\]]*:(?:(?P<v>[^\s/<>?#\[\]]{3,8192})"
                           r"|(?P<w>(?!\d+(?:[/?#]|\Z))[^\s<>\[\]]{3,256}?))@(?=[^\s@/])")
_PEM_BEGIN = re.compile(rf"-----BEGIN {_PEM_NAME}-----")
_PEM_END = re.compile(rf"-----END {_PEM_NAME}-----")
_KEY_SEPARATOR = re.compile(r"(?:\s|\\r|\\n|(?:>|\#|//|\*)(?=\s))*")     # also \n in JSON, > quotes
_KEY_HEADER = re.compile(r"(?:Version|Comment|Hash|Charset|Proc-Type|DEK-Info|MessageID)[ \t]*:[^\n]*")
_KEY_LINE = re.compile(r"(?:[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9+/]+={1,2}|=[A-Za-z0-9+/]{4})(?=\s|\\|[\"']|\Z)")
_KEY_LAST_LINE = re.compile(r"[A-Za-z0-9+/]+(?=(?:\s|\\r|\\n)*-----END)")
_BASE64_MARK = re.compile(r"[0-9+/=]")


def _key_block_end(text, pos):
    """Where the key after a BEGIN line ends, or None if no key material follows it, as when a
    note just mentions the marker. Only lines that look like a key are taken, with or without an
    END line: masking is irreversible, so prose next to a cut-off key must survive."""
    last, in_body = None, False
    while True:
        start = _KEY_SEPARATOR.match(text, pos).end()
        if in_body and text.count("\n", pos, start) >= 2:
            return last                  # a blank line ends the body
        end = _PEM_END.match(text, start)
        if end:
            return end.end() if in_body else None
        header = None if in_body else _KEY_HEADER.match(text, start)
        if header:
            pos = header.end()
            continue
        line = _KEY_LINE.match(text, start)
        if not line or not _BASE64_MARK.search(line.group()):
            line = _KEY_LAST_LINE.match(text, start)
        if not line:
            return last
        last, pos, in_body = line.end(), line.end(), True


def _private_keys(text):
    pos = 0
    while True:
        begin = _PEM_BEGIN.search(text, pos)
        if not begin:
            return
        end = _key_block_end(text, begin.end())
        pos = begin.end()
        if end is not None:
            yield begin.start(), end
            pos = end


def _format_matches(text):
    for name, rx in _FORMATS:
        group = "v" if "v" in rx.groupindex else 0
        for m in rx.finditer(text):
            before = text[m.start() - 1:m.start()]
            if before and (before.isalnum() or before in "_-") and group == 0:
                continue                 # inside a longer word: disk-sk-..., xAKIA...
            value = m.group(group)
            if group == "v" and value.lower() == value and not any(c.isdigit() for c in value):
                continue                 # "bearer authentication/authorization" is prose
            if not _DEMO_TOKEN.search(value):
                yield name, m.start(group), m.end(group), value
    for start, end in _private_keys(text):
        yield "private-key", start, end, text[start:end]


def _url_matches(text):
    for m in _URL_PASSWORD.finditer(text):
        group = "v" if m.group("v") else "w"
        value = m.group(group)
        verdict = classify(value, quoted=True)
        if group == "w":                 # a slash in it: only if it cannot be a path
            found = _strong_with_digit(value, verdict)
        else:                            # 123456 from a manual stays
            found = verdict == "strong" or (verdict == "weak" and _TWO_WORDS.match(value) and len(value) >= 8)
        if found:
            yield m.start(group), m.end(group), value


def prompt_candidates(text, deadline=None):
    """[(value, strength)] for everything in a user's message that looks like a secret."""
    found = {}

    def note(value, strength):
        if found.get(value) != "strong":
            found[value] = strength

    try:
        for value, verdict, _tier in _labelled(text, deadline=deadline):
            note(value.base, verdict)
            if value.text != value.base:
                note(value.text, verdict)
    except TooSlow:
        pass                             # an enormous paste: keep what was found, still do formats
    for _name, _start, _end, value in _format_matches(text):
        note(value, "strong")
    for _start, _end, value in _url_matches(text):
        note(value, "strong")
    return list(found.items())


# --- fingerprints --------------------------------------------------------------------------

def fingerprint(key, value):
    return hmac.digest(key, nfc(value).encode("utf-8", "surrogatepass"), "sha256").hex()


def _entries_for(key, value, strength):
    """One entry per length the value can take: precomposed and decomposed text differ. Values
    with line breaks, such as private keys, are found by format and cannot match by hash."""
    if "\n" in value or len(value) > MAX_VALUE:
        return []
    digest = fingerprint(key, value)
    lengths = {len(unicodedata.normalize(form, value)) for form in ("NFC", "NFD")}
    return [{"h": digest, "l": n, "f": strength} for n in sorted(lengths)]


def build_index(entries):
    index = {}
    for entry in entries or ():
        index.setdefault(entry["l"], {})[entry["h"]] = entry["f"]
    return index


_WEAK_GLUE = frozenset("-_.,+%$#/")
_KEYWORD_REACH = 120
_length_rx_cache = {}


def _glued(text, start, end):
    """Is this part of a longer token, as in ticket-4471 or 4471.5? A comma that ends a clause
    or a sentence's full stop does not count."""
    before, after = text[max(0, start - 2):start], text[end:end + 2]
    return ((len(before) == 2 and before[1] in _WEAK_GLUE and before[0].isalnum())
            or (len(after) == 2 and after[0] in _WEAK_GLUE and after[1].isalnum()))


def _length_rx(length):
    """Zero-width matches, overlapping, at every word edge followed by `length` characters and
    another edge. Anything other than a letter or digit is an edge; so is text in a script
    written without spaces. The search runs in C, so only these candidates get hashed."""
    if length not in _length_rx_cache:
        edge = rf"[\W_{_NO_SPACE}]"
        _length_rx_cache[length] = re.compile(
            rf"(?:(?<={edge})|^)(?=(\S[^\n]{{{length - 1}}})(?:{edge}|$))")
    return _length_rx_cache[length]


def _next_to_keyword(text, start):
    begin = max(0, start - _KEYWORD_REACH)
    head = text[max(text.rfind("\n", begin, start) + 1, begin):start]
    sentence = _SENTENCE_END.split(head)[-1]
    return any(lang.keywords.search(sentence) for lang in _languages())


def _fingerprint_matches(text, key, index, deadline=None):
    count = 0
    for length, table in index.items():
        for m in _length_rx(length).finditer(text):
            count += 1
            _check_deadline(deadline, count)
            start, end = m.start(), m.start() + length
            strength = table.get(fingerprint(key, m.group(1)))
            if strength is None:
                continue
            if strength == "weak":
                in_url = text[start - 1:start] == ":" and text[end:end + 1] == "@"
                if not in_url and (_glued(text, start, end) or not _next_to_keyword(text, start)):
                    continue
            yield start, end


def find_spans(text, key=None, index=None, deadline=None, fingerprints_only=False):
    """Sorted, non-overlapping [(start, end, kinds)] to replace in text."""
    spans = []
    if not fingerprints_only:
        for name, start, end, _value in _format_matches(text):
            spans.append((start, end, name))
        for value, verdict, _tier in _labelled(text, notes_only=True, deadline=deadline):
            if _worth_redacting(value.base, verdict):
                spans.append((value.start, value.end, "label"))
        for start, end, _value in _url_matches(text):
            spans.append((start, end, "url"))
    if key and index:
        for start, end in _fingerprint_matches(text, key, index, deadline):
            spans.append((start, end, "fingerprint"))
    spans.sort(key=lambda s: (s[0], -s[1]))
    merged = []
    for start, end, kind in spans:
        if merged and start < merged[-1][1]:       # overlap: hide the union, never leave a tail
            last = merged[-1]
            merged[-1] = (last[0], max(last[1], end), last[2] | {kind})
        else:
            merged.append((start, end, {kind}))
    return [m for m in merged if text[m[0]:m[1]] != TAG]


def apply_spans(text, spans):
    parts, pos = [], 0
    for start, end, _kinds in spans:
        parts += [text[pos:start], TAG]
        pos = end
    parts.append(text[pos:])
    return "".join(parts)


# --- paths ---------------------------------------------------------------------------------

class Paths:
    """Every location the tool uses. Nothing is read or created until it is asked for."""

    def __init__(self, env=None):
        self.env = os.environ if env is None else env
        self.home = os.path.expanduser("~")
        config = self.env.get("CLAUDE_CONFIG_DIR") or os.path.join(self.home, ".claude")
        self.config = os.path.abspath(os.path.expanduser(config))
        data = os.path.expanduser(self.env.get("CLAUDEPASSREDACTOR_DATA") or "")
        # A relative path would put the key in whatever folder a session happens to start in.
        self.data = os.path.abspath(data if os.path.isabs(data) else os.path.join(self.config, "claudepassredactor"))
        self.key = os.path.join(self.data, "key.bin")
        self.fingerprints = os.path.join(self.data, "fingerprints.json")
        self.state = os.path.join(self.data, "state.json")
        self.log = os.path.join(self.data, "redactor.log")
        self.lock = os.path.join(self.data, "lock")
        shared = os.path.expanduser(self.env.get("CLAUDEPASSREDACTOR_SHARED") or "")
        self.shared = os.path.abspath(shared) if os.path.isabs(shared) else None
        self.shared_refused = bool(shared) and self.shared is None


def _inside(root_real, path_real):
    base = os.path.normcase(root_real).rstrip("\\/") + os.sep
    return os.path.normcase(path_real).startswith(base)


def _safe_root(path, paths):
    """A root must not be a drive, the home folder or anything above it, or the config folder:
    a typo in a setting must not turn the tool loose on every note on the disk."""
    real = os.path.realpath(path)
    if os.path.dirname(real) == real:
        return False
    home = os.path.realpath(paths.home)
    same = os.path.normcase(real) == os.path.normcase(home)
    config = os.path.normcase(real) == os.path.normcase(os.path.realpath(paths.config))
    return not (same or config or _inside(real, home))


def memory_roots(paths):
    """CLAUDEPASSREDACTOR_DIRS if set; otherwise every <config>/projects/*/memory, user-level agent
    memory, and autoMemoryDirectory from the USER settings. Project settings are deliberately
    not read: a cloned repository must not be able to point this tool at other folders."""
    explicit = paths.env.get("CLAUDEPASSREDACTOR_DIRS")
    if explicit is not None:
        candidates = [p for p in explicit.split(os.pathsep) if p.strip()]
    else:
        candidates = []
        projects = os.path.join(paths.config, "projects")
        try:
            with os.scandir(projects) as entries:
                candidates += [os.path.join(e.path, "memory") for e in entries]
        except OSError:
            pass
        candidates.append(os.path.join(paths.config, "agent-memory"))
        try:
            with open(os.path.join(paths.config, "settings.json"), encoding="utf-8-sig") as f:
                custom = json.load(f).get("autoMemoryDirectory")
            if isinstance(custom, str):
                candidates.append(custom)
        except (OSError, ValueError, AttributeError):
            pass
    roots, seen = [], set()
    for raw in candidates:
        expanded = os.path.expanduser(raw.strip())
        if not os.path.isabs(expanded):
            continue                     # relative to what? A session can start anywhere.
        real = os.path.realpath(expanded)
        norm = os.path.normcase(real)
        if norm not in seen and os.path.isdir(real) and _safe_root(real, paths):
            seen.add(norm)
            roots.append(real)
    return roots


def roots_problem(paths, roots):
    """A folder asked for explicitly that cannot be used must not fail in silence."""
    explicit = paths.env.get("CLAUDEPASSREDACTOR_DIRS")
    if explicit is not None and len(roots) < max(1, len([p for p in explicit.split(os.pathsep) if p.strip()])):
        return "folder_refused"
    return None


def resolve_target(raw, cwd, roots):
    """The real path of a note named by a tool, or None if it is not a note in a memory root."""
    if not isinstance(raw, str) or not raw or "\0" in raw:
        return None
    path = raw if os.path.isabs(raw) else os.path.join(cwd if isinstance(cwd, str) and cwd else os.getcwd(), raw)
    real = os.path.realpath(path)
    if real.lower().endswith(".md"):
        for root in roots:
            if _inside(root, real):
                return None if ".git" in os.path.relpath(real, root).split(os.sep) else real
    return None


def iter_notes(roots, include_hidden=False):
    """The Markdown files inside the roots. Links out of a root, including Windows junctions,
    are not followed; hidden folders are skipped in hooks, and .git always."""
    for root in roots:
        for base, dirs, names in os.walk(root, followlinks=False):
            kept = []
            for d in dirs:
                if d == ".git" or (d.startswith(".") and not include_hidden):
                    continue
                if _inside(root, os.path.realpath(os.path.join(base, d))):
                    kept.append(d)
            dirs[:] = kept
            for name in names:
                if name.lower().endswith(".md"):
                    yield os.path.join(base, name)


# --- files: everything is written whole or not at all ---------------------------------------

def _windows_sid():
    import subprocess
    whoami = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "whoami.exe")
    try:
        result = subprocess.run([whoami, "/user", "/fo", "csv", "/nh"], capture_output=True, timeout=10,
                                creationflags=subprocess.CREATE_NO_WINDOW)
        return result.stdout.decode("ascii", "ignore").strip().rsplit(",", 1)[-1].strip('" \r\n') or None
    except (OSError, subprocess.SubprocessError):
        return None


def _restrict(path, directory=False):
    """Only the current user may open this: mode 0600/0700, or an equivalent ACL on Windows."""
    if os.name != "nt":
        try:
            os.chmod(path, 0o700 if directory else 0o600)
            return True
        except OSError:
            return False
    import subprocess
    sid = _windows_sid()
    if not sid:
        return False
    icacls = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")
    grant = f"*{sid}:(OI)(CI)F" if directory else f"*{sid}:F"
    try:
        return subprocess.run([icacls, path, "/inheritance:r", "/grant:r", grant],
                              capture_output=True, timeout=10,
                              creationflags=subprocess.CREATE_NO_WINDOW).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _ensure_private_dir(path):
    """A failure here leaves the folder as its parent would, and `status` then warns about it."""
    if not os.path.isdir(path):
        # On Windows the rules come only from _restrict. Recent Python versions turn mode 0o700 into
        # explicit rules for SYSTEM and Administrators, which /inheritance:r does not remove.
        os.makedirs(path, mode=0o777 if os.name == "nt" else 0o700, exist_ok=True)
        _restrict(path, directory=True)


def _replace(source, target):
    for delay in REPLACE_DELAYS + (None,):
        try:
            os.replace(source, target)
            return
        except PermissionError:
            if delay is None:
                raise
            time.sleep(delay)


def atomic_write(path, data, mode=None):
    """The file ends up with all of data or stays as it was. There is deliberately no fallback
    to writing in place: a failure there would leave a truncated file."""
    directory = os.path.dirname(path)
    # Syncthing never copies a file named like this, and a memory folder may be one it keeps in step.
    tmp = os.path.join(directory, f".syncthing.cpr-{secrets.token_hex(8)}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        if mode is not None and os.name != "nt":
            os.chmod(tmp, mode)
        _replace(tmp, path)
        tmp = None
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass


def _write_private_json(path, obj):
    _ensure_private_dir(os.path.dirname(path))
    atomic_write(path, json.dumps(obj, ensure_ascii=True, indent=0).encode("ascii"), mode=0o600)


class _Lock:
    """An OS lock on a file in the data folder, released by the OS even if the process dies.
    If it cannot be taken in time the work goes ahead anyway: every write is still atomic, and
    a missed review is worse than an unlikely race."""

    def __init__(self, paths, timeout=None):
        self.paths, self.timeout, self.fd = paths, LOCK_TIMEOUT if timeout is None else timeout, None

    @property
    def held(self):
        return self.fd is not None

    def __enter__(self):
        try:
            _ensure_private_dir(self.paths.data)
            self.fd = os.open(self.paths.lock, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            log_event(self.paths, f"lock unavailable errno={exc.errno}")
            return self
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                self._acquire()
                return self
            except OSError as exc:
                if time.monotonic() >= deadline:
                    log_event(self.paths, f"lock not acquired errno={exc.errno}")
                    os.close(self.fd)
                    self.fd = None
                    return self
                time.sleep(0.03)

    def _acquire(self):
        if os.name == "nt":
            import msvcrt
            os.lseek(self.fd, 0, os.SEEK_SET)
            msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def __exit__(self, *_exc):
        if self.fd is None:
            return
        try:
            if os.name == "nt":
                import msvcrt
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        os.close(self.fd)
        self.fd = None


def log_event(paths, message):
    """Append one line. Callers pass counts, file names, error numbers: never note contents,
    never exception messages. Logging must not be able to break a hook."""
    try:
        _ensure_private_dir(paths.data)
        try:
            if os.path.getsize(paths.log) > LOG_MAX_BYTES:
                os.replace(paths.log, paths.log + ".1")
        except OSError:
            pass
        clean = "".join(c if c.isprintable() else "?" for c in message)
        line = time.strftime("%Y-%m-%d %H:%M:%S ") + clean + "\n"
        fd = os.open(paths.log, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
        try:
            os.write(fd, line.encode("utf-8", "backslashreplace"))
        finally:
            os.close(fd)
    except OSError:
        pass


def log_exception(paths, exc):
    """Type, errno and line only. A message could quote the data being processed."""
    tb, line = exc.__traceback__, 0
    while tb:
        line = tb.tb_lineno
        tb = tb.tb_next
    log_event(paths, f"ERROR {type(exc).__name__} errno={getattr(exc, 'errno', None)} line={line}")


# --- key, fingerprint store, state ----------------------------------------------------------

def _create_key(paths):
    _ensure_private_dir(paths.data)
    tmp = f"{paths.key}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(KEY_BYTES))
            f.flush()
            os.fsync(f.fileno())
        if not _restrict(tmp):
            log_event(paths, "could not restrict the permissions of the key")
        try:
            os.link(tmp, paths.key)      # atomic, and fails if another process got there first
        except FileExistsError:
            pass
        except (OSError, NotImplementedError, AttributeError):
            # No hard links on this file system: rename (Windows refuses to overwrite).
            if os.path.exists(paths.key):
                pass
            elif os.name == "nt":
                os.rename(tmp, paths.key)
                tmp = None
            else:
                _copy_exclusive(tmp, paths.key)
    finally:
        if tmp:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    log_event(paths, "new key created")


def _copy_exclusive(source, target):
    with open(source, "rb") as f:
        data = f.read()
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def load_key(paths, create=True):
    """(key, problem). The key is never replaced here. A key that cannot be trusted turns off
    fingerprint matching, visibly; a new one would silently orphan every stored fingerprint,
    and an empty one would make them guessable."""
    try:
        info = os.lstat(paths.key)
    except FileNotFoundError:
        if not create:
            return None, None
        entries, _ = load_fingerprints(paths, quarantine=False)
        if entries:
            return None, "key_missing"
        try:
            _create_key(paths)
            return load_key(paths, create=False)
        except OSError as exc:
            log_event(paths, f"could not create the key errno={exc.errno}")
            return None, "key_unreadable"
    except OSError:
        return None, "key_unreadable"
    if not stat.S_ISREG(info.st_mode):
        return None, "key_invalid"
    try:
        with open(paths.key, "rb") as f:
            key = f.read(KEY_BYTES + 1)
    except OSError:
        return None, "key_unreadable"
    if len(key) != KEY_BYTES:
        return None, "key_invalid"
    if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
        if _restrict(paths.key):
            log_event(paths, "key permissions were too open and have been tightened")
    return key, None


_ENTRY_HASH = re.compile(r"[0-9a-f]{64}\Z")


def _valid_entry(entry):
    return (isinstance(entry, dict) and isinstance(entry.get("h"), str) and _ENTRY_HASH.match(entry["h"])
            and type(entry.get("l")) is int and 1 <= entry["l"] <= MAX_VALUE
            and entry.get("f") in ("strong", "weak"))


def load_fingerprints(paths, quarantine=True):
    """(entries, problem). entries is None if the store could not be read: it must then not be
    written, or an unreadable store would be replaced by an empty one. A corrupt store is kept
    under another name, so nothing a repair could recover is lost."""
    try:
        with open(paths.fingerprints, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        return [], None
    except OSError:
        return None, "store_unreadable"
    try:
        data = json.loads(raw.decode("utf-8"))
        items = data["secrets"]
        if not isinstance(items, list):
            raise ValueError
    except (ValueError, KeyError, TypeError):
        if quarantine:
            aside = f"{paths.fingerprints}.corrupt-{time.strftime('%Y%m%d%H%M%S')}-{secrets.token_hex(2)}"
            try:
                os.replace(paths.fingerprints, aside)
                log_event(paths, "fingerprint store was corrupt and has been set aside")
            except OSError:
                return None, "store_corrupt"
            return [], "store_corrupt"
        return [], "store_corrupt"
    entries = [e for e in items if _valid_entry(e)]
    if len(entries) != len(items):
        log_event(paths, f"ignored {len(items) - len(entries)} malformed fingerprint entries")
    return entries, None


def save_fingerprints(paths, entries):
    _write_private_json(paths.fingerprints, {"v": STORE_VERSION, "secrets": entries})


def _pending_files(paths):
    try:
        return [os.path.join(paths.data, n) for n in os.listdir(paths.data) if n.startswith(_PENDING_PREFIX)]
    except OSError:
        return []


def remember(paths, lock, entries, new):
    """Store new fingerprints. Without the lock, the shared store cannot be rewritten safely: each
    process leaves its own small file, and the next one with the lock takes them in."""
    if not merge_entries(entries, new):
        return False
    if lock.held:
        save_fingerprints(paths, entries)
    else:
        name = f"{_PENDING_PREFIX}{secrets.token_hex(8)}.json"
        _write_private_json(os.path.join(paths.data, name), {"v": STORE_VERSION, "secrets": new})
    return True


def absorb_pending(paths, lock, entries):
    """With the lock held, take in what other processes had to leave aside."""
    files = _pending_files(paths) if lock.held and entries is not None else []
    found = []
    for path in files:
        try:
            with open(path, "rb") as f:
                items = json.loads(f.read().decode("utf-8"))["secrets"]
            found += [e for e in items if _valid_entry(e)]
        except (OSError, ValueError, KeyError, TypeError):
            pass
    if files:
        if merge_entries(entries, found):
            save_fingerprints(paths, entries)
        for path in files:
            try:
                os.unlink(path)
            except OSError:
                pass


def _key_check(key):
    """Tells whether two computers use the same key, without revealing it."""
    return hmac.digest(key, b"claudepassredactor key check", "sha256").hex()[:16]


def _shared_conflicts(paths):
    """Copies that Syncthing leaves beside a file changed on two computers at once."""
    folder, name = os.path.split(paths.shared)
    stem, ext = os.path.splitext(name)
    try:
        return [os.path.join(folder, n) for n in sorted(os.listdir(folder))
                if n.startswith(f"{stem}.sync-conflict-") and n.endswith(ext)]
    except OSError:
        return []


def _read_shared(path):
    """(entries, forgotten, key check) of a shared file. Raises if it cannot be read or is damaged."""
    with open(path, "rb") as f:
        data = json.loads(f.read().decode("utf-8"))
    items, forgotten = data["secrets"], data.get("forgotten", [])
    if not isinstance(items, list) or not isinstance(forgotten, list):
        raise ValueError("not a shared fingerprint file")
    return ([e for e in items if _valid_entry(e)],
            {h for h in forgotten if isinstance(h, str) and _ENTRY_HASH.match(h)},
            data.get("key_check"))


def sync_shared(paths, lock, key, entries, forgotten=(), revived=()):
    """Bring the local store and the shared file into step, and take in conflict copies. Returns a
    problem code or None. A shared file that cannot be read, or that was made with another key, is
    never replaced: a new one would lose what it holds, and hashes from another key match nothing.

    A value forgotten on any computer stays forgotten everywhere until it is given again, or the
    next computer to sync would bring it back from its own store."""
    if not paths.shared or key is None or entries is None or not lock.held:
        return None
    check, found, gone, on_disk = _key_check(key), [], set(forgotten), None
    conflicts = _shared_conflicts(paths)
    usable = []
    for path in [paths.shared] + conflicts:
        try:
            items, removed, other_check = _read_shared(path)
        except FileNotFoundError:
            continue
        except (OSError, ValueError, KeyError, TypeError) as exc:
            log_event(paths, f"could not read {os.path.basename(path)} ({type(exc).__name__})")
            if path == paths.shared:
                return "shared_unreadable"
            continue                     # left in place, in case it can be repaired by hand
        if other_check != check:
            log_event(paths, f"{os.path.basename(path)} was made with another key")
            return "shared_other_key"
        if path == paths.shared:
            on_disk = ({(e["h"], e["l"], e["f"]) for e in items}, removed)
        else:
            usable.append(path)
        found += items
        gone |= removed
    gone -= set(revived)
    changed = merge_entries(entries, found)
    kept = [e for e in entries if e["h"] not in gone]
    if changed or len(kept) != len(entries):
        entries[:] = kept
        save_fingerprints(paths, entries)
    # Only when something differs: a sync tool would otherwise see a change at every message.
    if on_disk != ({(e["h"], e["l"], e["f"]) for e in entries}, gone) or usable:
        _write_private_json(paths.shared, {"v": STORE_VERSION, "key_check": check, "secrets": entries,
                                           "forgotten": sorted(gone)})
    for path in usable:
        try:
            os.unlink(path)
        except OSError:
            pass
    return None


def _try_sync_shared(paths, lock, key, entries, **changes):
    try:
        return sync_shared(paths, lock, key, entries, **changes)
    except OSError as exc:
        log_event(paths, f"could not write the shared fingerprints errno={exc.errno}")
        return "shared_unwritable"


def merge_entries(entries, new):
    """Returns how many entries were added or made stronger."""
    by_id = {(e["h"], e["l"]): e for e in entries}
    changed = 0
    for entry in new:
        current = by_id.get((entry["h"], entry["l"]))
        if current is None:
            entries.append(entry)
            by_id[(entry["h"], entry["l"])] = entry
            changed += 1
        elif current["f"] == "weak" and entry["f"] == "strong":
            current["f"] = "strong"
            changed += 1
    return changed


def load_state(paths):
    """Only a cache of what has been reviewed: losing it means one full review, nothing worse."""
    try:
        with open(paths.state, "rb") as f:
            data = json.loads(f.read().decode("utf-8"))
        return data if isinstance(data, dict) and isinstance(data.get("files"), dict) else {"files": {}}
    except (OSError, ValueError):
        return {"files": {}}


def _store_signature(paths):
    try:
        info = os.stat(paths.fingerprints)
        return [info.st_mtime_ns, info.st_size]
    except OSError:
        return None


# --- reviewing notes ------------------------------------------------------------------------

_BOMS = ((b"\xff\xfe\x00\x00", "utf-32-le"), (b"\x00\x00\xfe\xff", "utf-32-be"),
         (b"\xef\xbb\xbf", "utf-8"), (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"))


def decode_note(data):
    """(text, bom, codec, errors), chosen so that encoding the text gives the same bytes back.
    UTF-16 is common on Windows: PowerShell 5 writes it with '>'. Bytes that are not UTF-8 are
    kept as they are; a file with many of them is read as Latin-1, which round-trips any byte."""
    for bom, codec in _BOMS:
        if data.startswith(bom):
            errors = "surrogateescape" if codec == "utf-8" else "strict"
            return data[len(bom):].decode(codec, errors), bom, codec, errors
    if data.count(b"\x00") * 100 > len(data):   # a stray NUL in a long note does not make it binary
        raise ValueError("not text")
    try:
        return data.decode("utf-8"), b"", "utf-8", "strict"
    except UnicodeDecodeError:
        pass
    text = data.decode("utf-8", "surrogateescape")
    invalid = sum(1 for c in text if "\udc80" <= c <= "\udcff")
    high = sum(1 for b in data if b >= 0x80)
    if invalid * 2 > high:
        return data.decode("latin-1"), b"", "latin-1", "strict"
    return text, b"", "utf-8", "surrogateescape"


def _read_note(path):
    """Read a regular file without following a link or blocking on a FIFO. (bytes, stat)."""
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise OSError("not a regular file")
        if info.st_size > MAX_NOTE_BYTES:
            raise OSError("too large")
        chunks = []
        while True:
            chunk = os.read(fd, 1 << 20)
            if not chunk:
                return b"".join(chunks), info
            chunks.append(chunk)
    finally:
        os.close(fd)


class Report:
    def __init__(self):
        self.changed = []      # {"path", "count", "kinds", "lines", ...}
        self.failed = []       # paths that could not be read or written

    @property
    def total(self):
        return sum(c["count"] for c in self.changed)


def _line_numbers(text, spans):
    lines, line, pos = [], 1, 0
    for start, _end, _kinds in spans:
        line += text.count("\n", pos, start)
        pos = start
        if not lines or lines[-1] != line:
            lines.append(line)
    return lines


def _review_note(path, key, index, report, dry_run, keep_text, deadline=None, fingerprints_only=False):
    """Returns the note's signature once it is known to be clean. Raises if it could not be
    read or written, and then the note is not marked as reviewed, so the next pass retries it."""
    for _attempt in range(3):
        data, info = _read_note(path)
        text, bom, codec, errors = decode_note(data)
        spans = find_spans(text, key, index, deadline, fingerprints_only)
        signature = [info.st_mtime_ns, info.st_size]
        if not spans:
            return signature
        entry = {"path": path, "count": len(spans), "kinds": sorted({k for s in spans for k in s[2]}),
                 "lines": _line_numbers(text, spans)}
        if dry_run:
            if keep_text:
                entry["text"], entry["spans"] = text, spans
            report.changed.append(entry)
            return signature
        new_data = bom + apply_spans(text, spans).encode(codec, errors)   # may raise: nothing touched yet
        current = os.lstat(path)
        if [current.st_mtime_ns, current.st_size] != signature:
            continue                     # changed while being read: start again from the new text
        if current.st_nlink > 1:
            entry["hard_link"] = True    # the other name keeps the old content
        atomic_write(path, new_data, mode=stat.S_IMODE(info.st_mode))
        report.changed.append(entry)
        after = os.lstat(path)
        return [after.st_mtime_ns, after.st_size]
    raise OSError("kept changing")


def review(paths, roots, key, index, state, targets=None, full=False, dry_run=False,
           include_hidden=False, keep_text=False, deadline=None, fresh_index=None):
    """Review the given notes, or every note that changed since the last pass. All notes are
    reviewed if the fingerprints changed. One failure never stops the others.

    fresh_index holds just the fingerprints added now: a note that has not changed was already
    clean of everything else, so only these need looking for, which is much faster.
    After the deadline (time.monotonic()), notes not reached stay unmarked for the next pass; a
    note that alone takes most of the time is reported and left until it changes, or until a
    review by hand, so that it cannot make every later message wait."""
    report = Report()
    known = state.get("files", {})
    signature_now = _store_signature(paths)
    if targets is None:
        full = full or (state.get("fingerprints") != signature_now and not fresh_index)
        seen, notes = {}, iter_notes(roots, include_hidden)
    else:
        seen, notes = dict(known), targets
    for path in notes:
        state_key = os.path.normcase(path)
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            seen.pop(state_key, None)
            continue
        except OSError:
            report.failed.append(path)
            continue
        if not stat.S_ISREG(info.st_mode):
            seen.pop(state_key, None)
            continue
        signature = [info.st_mtime_ns, info.st_size]
        unchanged = targets is None and not full and known.get(state_key) == signature
        if unchanged and not fresh_index:
            seen[state_key] = signature
            continue
        if deadline is not None and time.monotonic() > deadline:
            seen.pop(state_key, None)
            continue
        started = time.monotonic()
        try:
            seen[state_key] = _review_note(path, key, fresh_index if unchanged else index, report, dry_run,
                                           keep_text, deadline, fingerprints_only=unchanged)
        except TooSlow:
            if time.monotonic() - started >= HOOK_BUDGET / 2:
                seen[state_key] = signature
                report.failed.append(path)
                log_event(paths, f"ran out of time reviewing {os.path.basename(path)}; run: redact")
            else:                        # others used the time up: it gets its turn next pass
                seen.pop(state_key, None)
        except (OSError, ValueError) as exc:
            seen.pop(state_key, None)
            report.failed.append(path)
            log_event(paths, f"could not review {os.path.basename(path)} "
                             f"({type(exc).__name__} errno={getattr(exc, 'errno', None)})")
    for item in report.changed:
        if not dry_run:
            log_event(paths, f"redacted {item['count']} in {os.path.basename(item['path'])} "
                             f"(lines {item['lines']}; {', '.join(item['kinds'])})"
                             + ("; note has another hard link" if item.get("hard_link") else ""))
    if not dry_run:
        state["files"] = seen
        if targets is None:
            state["fingerprints"] = signature_now
    return report


# --- messages shown to the user -------------------------------------------------------------

MESSAGES = {
    "en": dict(
        detected="🔒 Possible secrets in this message: {n}. Any that reach a memory note will be replaced with {tag}.",
        redacted="🔒 Secrets replaced with {tag} in memory: {n} ({files}).",
        attention="⚠️ The memory redactor needs attention. Run: claudepassredactor.py status",
        key_problem="⚠️ Memory redactor: problem with its key, remembered secrets are not being looked for. Run: claudepassredactor.py status",
        nothing="Nothing to redact.", would="Would redact: {n}", done="Redacted: {n}",
        added="Fingerprint saved.", forgotten="Fingerprint removed.",
        not_found="No fingerprint for that value.", bad_length="Length must be between 4 and 8192 characters.",
        prompt_value="Value (hidden): ",
        stdin_value="Reading the value from standard input: if this is a terminal, it will be visible.",
        no_arguments="This command takes no arguments: it asks for the value, so that it stays out of the shell history. Nothing has been stored.",
        reset_confirm="This deletes the key and this computer's fingerprints, and secrets already given are no longer remembered. Notes are not touched. Repeat with --yes to go ahead.",
        reset_done="Key, fingerprints and state deleted.",
        reset_shared="The shared file is not deleted, because other computers use it: {path}. To keep sharing, copy key.bin back from another computer.",
        no_store="cannot store fingerprints: {problem}", no_read="cannot read fingerprints: {problem}",
        warn_earlier="warning: {problem}: secrets given earlier are not being looked for",
        warn_damaged="warning: {n} damaged fingerprint store(s) set aside in {path}: secrets given before that are no longer looked for",
        warn_folder="warning: a folder in CLAUDEPASSREDACTOR_DIRS was refused or does not exist",
        warn_shared="warning: shared fingerprints: {problem}",
        warn_shared_forget="warning: shared fingerprints: {problem}; the other computers keep this value",
        cannot_read="could not read: {path}", cannot_review="could not review: {path}",
        lines="lines {lines}", os_error="error: {detail}"),
    "es": dict(
        detected="🔒 Posibles secretos en este mensaje: {n}. Los que lleguen a una nota de memoria se cambiarán por {tag}.",
        redacted="🔒 Secretos cambiados por {tag} en la memoria: {n} ({files}).",
        attention="⚠️ El redactor de memoria necesita atención. Ejecuta: claudepassredactor.py status",
        key_problem="⚠️ Redactor de memoria: problema con su clave, los secretos recordados no se están buscando. Ejecuta: claudepassredactor.py status",
        nothing="Nada que tapar.", would="Se taparían: {n}", done="Tapados: {n}",
        added="Huella guardada.", forgotten="Huella eliminada.",
        not_found="No hay ninguna huella para ese valor.", bad_length="La longitud debe estar entre 4 y 8192 caracteres.",
        prompt_value="Valor (oculto): ",
        stdin_value="Leyendo el valor de la entrada estándar: si esto es una terminal, se verá en pantalla.",
        no_arguments="Este comando no lleva argumentos: pide el valor para que no quede en el historial de la terminal. No se ha guardado nada.",
        reset_confirm="Esto borra la clave y las huellas de este equipo, y los secretos ya dados dejan de recordarse. Las notas no se tocan. Repítelo con --yes para continuar.",
        reset_done="Clave, huellas y estado borrados.",
        reset_shared="El fichero compartido no se borra, porque lo usan otros equipos: {path}. Para seguir compartiendo, vuelve a copiar key.bin desde otro equipo.",
        no_store="no se pueden guardar las huellas: {problem}", no_read="no se pueden leer las huellas: {problem}",
        warn_earlier="aviso: {problem}: no se están buscando los secretos dados antes",
        warn_damaged="aviso: {n} almacén(es) de huellas dañados apartados en {path}: los secretos dados antes de eso ya no se buscan",
        warn_folder="aviso: una carpeta de CLAUDEPASSREDACTOR_DIRS se ha rechazado o no existe",
        warn_shared="aviso: huellas compartidas: {problem}",
        warn_shared_forget="aviso: huellas compartidas: {problem}; los demás equipos conservan este valor",
        cannot_read="no se ha podido leer: {path}", cannot_review="no se ha podido revisar: {path}",
        lines="líneas {lines}", os_error="error: {detail}"),
    "pt": dict(
        detected="🔒 Possíveis segredos nesta mensagem: {n}. Os que chegarem a uma nota de memória serão substituídos por {tag}.",
        redacted="🔒 Segredos substituídos por {tag} na memória: {n} ({files}).",
        attention="⚠️ O redator de memória precisa de atenção. Execute: claudepassredactor.py status",
        key_problem="⚠️ Redator de memória: problema com a chave, os segredos guardados não estão a ser procurados. Execute: claudepassredactor.py status",
        nothing="Nada para ocultar.", would="Seriam ocultados: {n}", done="Ocultados: {n}",
        added="Impressão guardada.", forgotten="Impressão removida.",
        not_found="Não há impressão para esse valor.", bad_length="O tamanho deve estar entre 4 e 8192 caracteres.",
        prompt_value="Valor (oculto): ",
        stdin_value="A ler o valor da entrada padrão: se isto for um terminal, ficará visível.",
        no_arguments="Este comando não aceita argumentos: pede o valor para que não fique no histórico do terminal. Nada foi guardado.",
        reset_confirm="Isto apaga a chave e as impressões deste computador, e os segredos já dados deixam de ser lembrados. As notas não são alteradas. Repita com --yes para continuar.",
        reset_done="Chave, impressões e estado apagados.",
        reset_shared="O ficheiro partilhado não é apagado, porque outros computadores o usam: {path}. Para continuar a partilhar, copie de novo key.bin de outro computador.",
        no_store="não é possível guardar as impressões: {problem}", no_read="não é possível ler as impressões: {problem}",
        warn_earlier="aviso: {problem}: os segredos dados antes não estão a ser procurados",
        warn_damaged="aviso: {n} arquivo(s) de impressões danificado(s) postos de lado em {path}: os segredos dados antes disso já não são procurados",
        warn_folder="aviso: uma pasta de CLAUDEPASSREDACTOR_DIRS foi recusada ou não existe",
        warn_shared="aviso: impressões partilhadas: {problem}",
        warn_shared_forget="aviso: impressões partilhadas: {problem}; os outros computadores mantêm este valor",
        cannot_read="não foi possível ler: {path}", cannot_review="não foi possível rever: {path}",
        lines="linhas {lines}", os_error="erro: {detail}"),
    "fr": dict(
        detected="🔒 Secrets possibles dans ce message : {n}. Ceux qui arrivent dans une note de mémoire seront remplacés par {tag}.",
        redacted="🔒 Secrets remplacés par {tag} dans la mémoire : {n} ({files}).",
        attention="⚠️ Le masqueur de mémoire demande votre attention. Lancez : claudepassredactor.py status",
        key_problem="⚠️ Masqueur de mémoire : problème de clé, les secrets mémorisés ne sont plus recherchés. Lancez : claudepassredactor.py status",
        nothing="Rien à masquer.", would="Seraient masqués : {n}", done="Masqués : {n}",
        added="Empreinte enregistrée.", forgotten="Empreinte supprimée.",
        not_found="Aucune empreinte pour cette valeur.", bad_length="La longueur doit être comprise entre 4 et 8192 caractères.",
        prompt_value="Valeur (masquée) : ",
        stdin_value="Lecture de la valeur sur l'entrée standard : si c'est un terminal, elle sera visible.",
        no_arguments="Cette commande ne prend aucun argument : elle demande la valeur pour qu'elle n'apparaisse pas dans l'historique du terminal. Rien n'a été enregistré.",
        reset_confirm="Ceci supprime la clé et les empreintes de cet ordinateur, et les secrets déjà donnés ne sont plus mémorisés. Les notes ne sont pas modifiées. Relancez avec --yes pour continuer.",
        reset_done="Clé, empreintes et état supprimés.",
        reset_shared="Le fichier partagé n'est pas supprimé, car d'autres ordinateurs l'utilisent : {path}. Pour continuer à partager, recopiez key.bin depuis un autre ordinateur.",
        no_store="impossible d'enregistrer les empreintes : {problem}", no_read="impossible de lire les empreintes : {problem}",
        warn_earlier="avertissement : {problem} : les secrets donnés auparavant ne sont pas recherchés",
        warn_damaged="avertissement : {n} magasin(s) d'empreintes endommagé(s) mis de côté dans {path} : les secrets donnés avant cela ne sont plus recherchés",
        warn_folder="avertissement : un dossier de CLAUDEPASSREDACTOR_DIRS a été refusé ou n'existe pas",
        warn_shared="avertissement : empreintes partagées : {problem}",
        warn_shared_forget="avertissement : empreintes partagées : {problem} ; les autres ordinateurs conservent cette valeur",
        cannot_read="lecture impossible : {path}", cannot_review="vérification impossible : {path}",
        lines="lignes {lines}", os_error="erreur : {detail}"),
    "de": dict(
        detected="🔒 Mögliche Geheimnisse in dieser Nachricht: {n}. Was in einer Speichernotiz landet, wird durch {tag} ersetzt.",
        redacted="🔒 Geheimnisse im Speicher durch {tag} ersetzt: {n} ({files}).",
        attention="⚠️ Der Speicher-Schwärzer braucht Aufmerksamkeit. Ausführen: claudepassredactor.py status",
        key_problem="⚠️ Speicher-Schwärzer: Problem mit dem Schlüssel, gemerkte Geheimnisse werden nicht gesucht. Ausführen: claudepassredactor.py status",
        nothing="Nichts zu schwärzen.", would="Würde schwärzen: {n}", done="Geschwärzt: {n}",
        added="Fingerabdruck gespeichert.", forgotten="Fingerabdruck entfernt.",
        not_found="Kein Fingerabdruck für diesen Wert.", bad_length="Die Länge muss zwischen 4 und 8192 Zeichen liegen.",
        prompt_value="Wert (verborgen): ",
        stdin_value="Der Wert wird von der Standardeingabe gelesen: In einem Terminal ist er sichtbar.",
        no_arguments="Dieser Befehl nimmt keine Argumente: Er fragt nach dem Wert, damit dieser nicht im Shell-Verlauf landet. Es wurde nichts gespeichert.",
        reset_confirm="Dies löscht den Schlüssel und die Fingerabdrücke dieses Computers, und bereits angegebene Geheimnisse werden nicht mehr gemerkt. Notizen bleiben unverändert. Zum Fortfahren mit --yes wiederholen.",
        reset_done="Schlüssel, Fingerabdrücke und Status gelöscht.",
        reset_shared="Die gemeinsame Datei wird nicht gelöscht, weil andere Computer sie nutzen: {path}. Um weiter zu teilen, kopiere key.bin erneut von einem anderen Computer.",
        no_store="Fingerabdrücke können nicht gespeichert werden: {problem}", no_read="Fingerabdrücke können nicht gelesen werden: {problem}",
        warn_earlier="Warnung: {problem}: früher angegebene Geheimnisse werden nicht gesucht",
        warn_damaged="Warnung: {n} beschädigte(r) Fingerabdruckspeicher in {path} beiseitegelegt: davor angegebene Geheimnisse werden nicht mehr gesucht",
        warn_folder="Warnung: Ein Ordner in CLAUDEPASSREDACTOR_DIRS wurde abgelehnt oder existiert nicht",
        warn_shared="Warnung: gemeinsame Fingerabdrücke: {problem}",
        warn_shared_forget="Warnung: gemeinsame Fingerabdrücke: {problem}; die anderen Computer behalten diesen Wert",
        cannot_read="Konnte nicht gelesen werden: {path}", cannot_review="Konnte nicht geprüft werden: {path}",
        lines="Zeilen {lines}", os_error="Fehler: {detail}"),
    "it": dict(
        detected="🔒 Possibili segreti in questo messaggio: {n}. Quelli che arrivano in una nota di memoria saranno sostituiti con {tag}.",
        redacted="🔒 Segreti sostituiti con {tag} nella memoria: {n} ({files}).",
        attention="⚠️ Il censore della memoria richiede attenzione. Esegui: claudepassredactor.py status",
        key_problem="⚠️ Censore della memoria: problema con la chiave, i segreti ricordati non vengono cercati. Esegui: claudepassredactor.py status",
        nothing="Niente da oscurare.", would="Verrebbero oscurati: {n}", done="Oscurati: {n}",
        added="Impronta salvata.", forgotten="Impronta rimossa.",
        not_found="Nessuna impronta per quel valore.", bad_length="La lunghezza deve essere compresa tra 4 e 8192 caratteri.",
        prompt_value="Valore (nascosto): ",
        stdin_value="Lettura del valore dallo standard input: se questo è un terminale, sarà visibile.",
        no_arguments="Questo comando non accetta argomenti: chiede il valore perché non resti nella cronologia del terminale. Non è stato salvato nulla.",
        reset_confirm="Questo elimina la chiave e le impronte di questo computer, e i segreti già forniti non vengono più ricordati. Le note non vengono toccate. Ripeti con --yes per procedere.",
        reset_done="Chiave, impronte e stato eliminati.",
        reset_shared="Il file condiviso non viene eliminato, perché lo usano altri computer: {path}. Per continuare a condividere, copia di nuovo key.bin da un altro computer.",
        no_store="impossibile salvare le impronte: {problem}", no_read="impossibile leggere le impronte: {problem}",
        warn_earlier="avviso: {problem}: i segreti forniti in precedenza non vengono cercati",
        warn_damaged="avviso: {n} archivi di impronte danneggiati messi da parte in {path}: i segreti forniti prima non vengono più cercati",
        warn_folder="avviso: una cartella in CLAUDEPASSREDACTOR_DIRS è stata rifiutata o non esiste",
        warn_shared="avviso: impronte condivise: {problem}",
        warn_shared_forget="avviso: impronte condivise: {problem}; gli altri computer conservano questo valore",
        cannot_read="impossibile leggere: {path}", cannot_review="impossibile controllare: {path}",
        lines="righe {lines}", os_error="errore: {detail}"),
    "nl": dict(
        detected="🔒 Mogelijke geheimen in dit bericht: {n}. Wat in een geheugennotitie belandt, wordt vervangen door {tag}.",
        redacted="🔒 Geheimen vervangen door {tag} in het geheugen: {n} ({files}).",
        attention="⚠️ De geheugenredacteur vraagt aandacht. Voer uit: claudepassredactor.py status",
        key_problem="⚠️ Geheugenredacteur: probleem met de sleutel, onthouden geheimen worden niet gezocht. Voer uit: claudepassredactor.py status",
        nothing="Niets af te schermen.", would="Zou afschermen: {n}", done="Afgeschermd: {n}",
        added="Vingerafdruk opgeslagen.", forgotten="Vingerafdruk verwijderd.",
        not_found="Geen vingerafdruk voor die waarde.", bad_length="De lengte moet tussen 4 en 8192 tekens liggen.",
        prompt_value="Waarde (verborgen): ",
        stdin_value="De waarde wordt van standaardinvoer gelezen: in een terminal is die zichtbaar.",
        no_arguments="Deze opdracht neemt geen argumenten: ze vraagt om de waarde, zodat die niet in de shellgeschiedenis belandt. Er is niets opgeslagen.",
        reset_confirm="Dit verwijdert de sleutel en de vingerafdrukken van deze computer, en eerder gegeven geheimen worden niet meer onthouden. Notities blijven ongemoeid. Herhaal met --yes om door te gaan.",
        reset_done="Sleutel, vingerafdrukken en status verwijderd.",
        reset_shared="Het gedeelde bestand wordt niet verwijderd, omdat andere computers het gebruiken: {path}. Kopieer key.bin opnieuw van een andere computer om te blijven delen.",
        no_store="vingerafdrukken kunnen niet worden opgeslagen: {problem}", no_read="vingerafdrukken kunnen niet worden gelezen: {problem}",
        warn_earlier="waarschuwing: {problem}: eerder gegeven geheimen worden niet gezocht",
        warn_damaged="waarschuwing: {n} beschadigde vingerafdrukopslag(en) apart gezet in {path}: daarvoor gegeven geheimen worden niet meer gezocht",
        warn_folder="waarschuwing: een map in CLAUDEPASSREDACTOR_DIRS is geweigerd of bestaat niet",
        warn_shared="waarschuwing: gedeelde vingerafdrukken: {problem}",
        warn_shared_forget="waarschuwing: gedeelde vingerafdrukken: {problem}; de andere computers houden deze waarde",
        cannot_read="kon niet lezen: {path}", cannot_review="kon niet controleren: {path}",
        lines="regels {lines}", os_error="fout: {detail}"),
    "pl": dict(
        detected="🔒 Możliwe sekrety w tej wiadomości: {n}. Te, które trafią do notatki pamięci, zostaną zastąpione przez {tag}.",
        redacted="🔒 Sekrety zastąpione przez {tag} w pamięci: {n} ({files}).",
        attention="⚠️ Redaktor pamięci wymaga uwagi. Uruchom: claudepassredactor.py status",
        key_problem="⚠️ Redaktor pamięci: problem z kluczem, zapamiętane sekrety nie są wyszukiwane. Uruchom: claudepassredactor.py status",
        nothing="Nie ma czego ukrywać.", would="Do ukrycia: {n}", done="Ukryto: {n}",
        added="Odcisk zapisany.", forgotten="Odcisk usunięty.",
        not_found="Brak odcisku dla tej wartości.", bad_length="Długość musi wynosić od 4 do 8192 znaków.",
        prompt_value="Wartość (ukryta): ",
        stdin_value="Odczyt wartości ze standardowego wejścia: w terminalu będzie widoczna.",
        no_arguments="To polecenie nie przyjmuje argumentów: pyta o wartość, aby nie trafiła do historii powłoki. Niczego nie zapisano.",
        reset_confirm="To usuwa klucz i odciski z tego komputera, a podane już sekrety przestają być pamiętane. Notatki pozostają bez zmian. Powtórz z --yes, aby kontynuować.",
        reset_done="Klucz, odciski i stan usunięte.",
        reset_shared="Wspólny plik nie jest usuwany, bo korzystają z niego inne komputery: {path}. Aby dalej współdzielić, skopiuj ponownie key.bin z innego komputera.",
        no_store="nie można zapisać odcisków: {problem}", no_read="nie można odczytać odcisków: {problem}",
        warn_earlier="ostrzeżenie: {problem}: wcześniej podane sekrety nie są wyszukiwane",
        warn_damaged="ostrzeżenie: uszkodzone magazyny odcisków odłożone w {path} (liczba: {n}): podane wcześniej sekrety nie są już wyszukiwane",
        warn_folder="ostrzeżenie: folder w CLAUDEPASSREDACTOR_DIRS został odrzucony lub nie istnieje",
        warn_shared="ostrzeżenie: wspólne odciski: {problem}",
        warn_shared_forget="ostrzeżenie: wspólne odciski: {problem}; pozostałe komputery zachowują tę wartość",
        cannot_read="nie można odczytać: {path}", cannot_review="nie można sprawdzić: {path}",
        lines="wiersze {lines}", os_error="błąd: {detail}"),
    "ru": dict(
        detected="🔒 Возможные секреты в этом сообщении: {n}. Те, что попадут в заметку памяти, будут заменены на {tag}.",
        redacted="🔒 Секреты заменены на {tag} в памяти: {n} ({files}).",
        attention="⚠️ Редактору памяти нужно внимание. Выполните: claudepassredactor.py status",
        key_problem="⚠️ Редактор памяти: проблема с ключом, сохранённые секреты не ищутся. Выполните: claudepassredactor.py status",
        nothing="Скрывать нечего.", would="Будет скрыто: {n}", done="Скрыто: {n}",
        added="Отпечаток сохранён.", forgotten="Отпечаток удалён.",
        not_found="Для этого значения нет отпечатка.", bad_length="Длина должна быть от 4 до 8192 символов.",
        prompt_value="Значение (скрыто): ",
        stdin_value="Значение читается из стандартного ввода: в терминале оно будет видно.",
        no_arguments="Эта команда не принимает аргументов: она запрашивает значение, чтобы оно не попало в историю оболочки. Ничего не сохранено.",
        reset_confirm="Это удалит ключ и отпечатки на этом компьютере, и уже указанные секреты больше не будут запоминаться. Заметки не затрагиваются. Повторите с --yes, чтобы продолжить.",
        reset_done="Ключ, отпечатки и состояние удалены.",
        reset_shared="Общий файл не удаляется, потому что его используют другие компьютеры: {path}. Чтобы продолжить общий доступ, снова скопируйте key.bin с другого компьютера.",
        no_store="не удаётся сохранить отпечатки: {problem}", no_read="не удаётся прочитать отпечатки: {problem}",
        warn_earlier="предупреждение: {problem}: ранее указанные секреты не ищутся",
        warn_damaged="предупреждение: повреждённые хранилища отпечатков отложены в {path} (всего: {n}): секреты, указанные до этого, больше не ищутся",
        warn_folder="предупреждение: папка из CLAUDEPASSREDACTOR_DIRS отклонена или не существует",
        warn_shared="предупреждение: общие отпечатки: {problem}",
        warn_shared_forget="предупреждение: общие отпечатки: {problem}; на других компьютерах это значение останется",
        cannot_read="не удалось прочитать: {path}", cannot_review="не удалось проверить: {path}",
        lines="строки {lines}", os_error="ошибка: {detail}"),
    "uk": dict(
        detected="🔒 Можливі секрети в цьому повідомленні: {n}. Ті, що потраплять до нотатки пам'яті, буде замінено на {tag}.",
        redacted="🔒 Секрети замінено на {tag} у пам'яті: {n} ({files}).",
        attention="⚠️ Редактор пам'яті потребує уваги. Виконайте: claudepassredactor.py status",
        key_problem="⚠️ Редактор пам'яті: проблема з ключем, збережені секрети не шукаються. Виконайте: claudepassredactor.py status",
        nothing="Нічого приховувати.", would="Буде приховано: {n}", done="Приховано: {n}",
        added="Відбиток збережено.", forgotten="Відбиток видалено.",
        not_found="Для цього значення немає відбитка.", bad_length="Довжина має бути від 4 до 8192 символів.",
        prompt_value="Значення (приховано): ",
        stdin_value="Значення читається зі стандартного вводу: у терміналі його буде видно.",
        no_arguments="Ця команда не приймає аргументів: вона запитує значення, щоб воно не потрапило до історії оболонки. Нічого не збережено.",
        reset_confirm="Це видалить ключ і відбитки на цьому комп'ютері, і вже вказані секрети більше не запам'ятовуватимуться. Нотатки не змінюються. Повторіть із --yes, щоб продовжити.",
        reset_done="Ключ, відбитки та стан видалено.",
        reset_shared="Спільний файл не видаляється, бо його використовують інші комп'ютери: {path}. Щоб і далі ділитися, знову скопіюйте key.bin з іншого комп'ютера.",
        no_store="не вдається зберегти відбитки: {problem}", no_read="не вдається прочитати відбитки: {problem}",
        warn_earlier="попередження: {problem}: раніше вказані секрети не шукаються",
        warn_damaged="попередження: пошкоджені сховища відбитків відкладено в {path} (усього: {n}): секрети, вказані до цього, більше не шукаються",
        warn_folder="попередження: теку з CLAUDEPASSREDACTOR_DIRS відхилено або вона не існує",
        warn_shared="попередження: спільні відбитки: {problem}",
        warn_shared_forget="попередження: спільні відбитки: {problem}; на інших комп'ютерах це значення залишиться",
        cannot_read="не вдалося прочитати: {path}", cannot_review="не вдалося перевірити: {path}",
        lines="рядки {lines}", os_error="помилка: {detail}"),
    "zh-CN": dict(
        detected="🔒 此消息中可能包含的机密数量：{n}。写入记忆笔记的内容将被替换为 {tag}。",
        redacted="🔒 记忆中已替换为 {tag} 的机密数量：{n}（{files}）。",
        attention="⚠️ 记忆脱敏工具需要处理。请运行：claudepassredactor.py status",
        key_problem="⚠️ 记忆脱敏工具：密钥有问题，已记录的机密未被查找。请运行：claudepassredactor.py status",
        nothing="没有需要遮盖的内容。", would="将遮盖：{n}", done="已遮盖：{n}",
        added="指纹已保存。", forgotten="指纹已删除。",
        not_found="该值没有对应的指纹。", bad_length="长度必须在 4 到 8192 个字符之间。",
        prompt_value="值（隐藏）：",
        stdin_value="正在从标准输入读取该值：如果这是终端，它将可见。",
        no_arguments="此命令不接受参数：它会询问该值，以免其留在 shell 历史记录中。未保存任何内容。",
        reset_confirm="这将删除此计算机上的密钥和指纹，已提供的机密将不再被记住。笔记不受影响。使用 --yes 重新运行以继续。",
        reset_done="密钥、指纹和状态已删除。",
        reset_shared="共享文件不会被删除，因为其他计算机在使用它：{path}。要继续共享，请从另一台计算机重新复制 key.bin。",
        no_store="无法保存指纹：{problem}", no_read="无法读取指纹：{problem}",
        warn_earlier="警告：{problem}：未查找之前提供的机密",
        warn_damaged="警告：{n} 个损坏的指纹存储已移至 {path}：在此之前提供的机密不再被查找",
        warn_folder="警告：CLAUDEPASSREDACTOR_DIRS 中的某个文件夹被拒绝或不存在",
        warn_shared="警告：共享指纹：{problem}",
        warn_shared_forget="警告：共享指纹：{problem}；其他计算机仍保留此值",
        cannot_read="无法读取：{path}", cannot_review="无法检查：{path}",
        lines="第 {lines} 行", os_error="错误：{detail}"),
    "ja": dict(
        detected="🔒 このメッセージに含まれる可能性のある機密情報：{n} 件。メモリのノートに書かれたものは {tag} に置き換えられます。",
        redacted="🔒 メモリ内で {tag} に置き換えた機密情報：{n} 件（{files}）。",
        attention="⚠️ メモリ墨消しツールの確認が必要です。実行：claudepassredactor.py status",
        key_problem="⚠️ メモリ墨消しツール：鍵に問題があり、記録済みの機密情報を検索していません。実行：claudepassredactor.py status",
        nothing="隠すものはありません。", would="隠す予定：{n} 件", done="隠しました：{n} 件",
        added="指紋を保存しました。", forgotten="指紋を削除しました。",
        not_found="その値の指紋はありません。", bad_length="長さは 4 ～ 8192 文字にしてください。",
        prompt_value="値（非表示）：",
        stdin_value="標準入力から値を読み取ります。端末の場合は値が表示されます。",
        no_arguments="このコマンドは引数を取りません。シェルの履歴に残らないよう、値を尋ねます。何も保存していません。",
        reset_confirm="このコンピュータの鍵と指紋を削除し、すでに渡した機密情報は記憶されなくなります。ノートは変更されません。続行するには --yes を付けて再実行してください。",
        reset_done="鍵、指紋、状態を削除しました。",
        reset_shared="共有ファイルは他のコンピュータが使っているため削除しません：{path}。共有を続けるには、別のコンピュータから key.bin をコピーし直してください。",
        no_store="指紋を保存できません：{problem}", no_read="指紋を読み取れません：{problem}",
        warn_earlier="警告：{problem}：以前に渡した機密情報を検索していません",
        warn_damaged="警告：破損した指紋ストア {n} 件を {path} に退避しました。それ以前に渡した機密情報は検索されなくなります",
        warn_folder="警告：CLAUDEPASSREDACTOR_DIRS のフォルダが拒否されたか、存在しません",
        warn_shared="警告：共有の指紋：{problem}",
        warn_shared_forget="警告：共有の指紋：{problem}。他のコンピュータにはこの値が残ります",
        cannot_read="読み取れません：{path}", cannot_review="確認できません：{path}",
        lines="{lines} 行目", os_error="エラー：{detail}"),
    "ko": dict(
        detected="🔒 이 메시지에 포함된 비밀로 보이는 항목: {n}개. 메모리 노트에 기록되면 {tag}(으)로 바뀝니다.",
        redacted="🔒 메모리에서 {tag}(으)로 바꾼 비밀: {n}개 ({files}).",
        attention="⚠️ 메모리 가림 도구를 확인해야 합니다. 실행: claudepassredactor.py status",
        key_problem="⚠️ 메모리 가림 도구: 키에 문제가 있어 기억된 비밀을 찾지 않습니다. 실행: claudepassredactor.py status",
        nothing="가릴 내용이 없습니다.", would="가릴 항목: {n}개", done="가린 항목: {n}개",
        added="지문을 저장했습니다.", forgotten="지문을 삭제했습니다.",
        not_found="해당 값의 지문이 없습니다.", bad_length="길이는 4~8192자여야 합니다.",
        prompt_value="값(숨김): ",
        stdin_value="표준 입력에서 값을 읽습니다. 터미널이면 값이 화면에 보입니다.",
        no_arguments="이 명령은 인수를 받지 않습니다. 셸 기록에 남지 않도록 값을 직접 묻습니다. 아무것도 저장하지 않았습니다.",
        reset_confirm="이 컴퓨터의 키와 지문을 삭제하며, 이미 입력한 비밀은 더 이상 기억되지 않습니다. 노트는 변경되지 않습니다. 계속하려면 --yes를 붙여 다시 실행하세요.",
        reset_done="키, 지문, 상태를 삭제했습니다.",
        reset_shared="공유 파일은 다른 컴퓨터가 사용하므로 삭제하지 않습니다: {path}. 계속 공유하려면 다른 컴퓨터에서 key.bin을 다시 복사하세요.",
        no_store="지문을 저장할 수 없습니다: {problem}", no_read="지문을 읽을 수 없습니다: {problem}",
        warn_earlier="경고: {problem}: 이전에 입력한 비밀을 찾지 않습니다",
        warn_damaged="경고: 손상된 지문 저장소 {n}개를 {path}에 옮겨 두었습니다. 그 이전에 입력한 비밀은 더 이상 찾지 않습니다",
        warn_folder="경고: CLAUDEPASSREDACTOR_DIRS의 폴더가 거부되었거나 존재하지 않습니다",
        warn_shared="경고: 공유 지문: {problem}",
        warn_shared_forget="경고: 공유 지문: {problem}. 다른 컴퓨터에는 이 값이 남습니다",
        cannot_read="읽을 수 없습니다: {path}", cannot_review="확인할 수 없습니다: {path}",
        lines="{lines}행", os_error="오류: {detail}"),
    "th": dict(
        detected="🔒 ข้อมูลลับที่อาจมีในข้อความนี้: {n} รายการ หากถูกเขียนลงในบันทึกความจำจะถูกแทนที่ด้วย {tag}",
        redacted="🔒 แทนที่ข้อมูลลับด้วย {tag} ในความจำแล้ว: {n} รายการ ({files})",
        attention="⚠️ เครื่องมือปกปิดความจำต้องได้รับการตรวจสอบ เรียกใช้: claudepassredactor.py status",
        key_problem="⚠️ เครื่องมือปกปิดความจำ: กุญแจมีปัญหา จึงไม่ได้ค้นหาข้อมูลลับที่จำไว้ เรียกใช้: claudepassredactor.py status",
        nothing="ไม่มีอะไรต้องปกปิด", would="จะปกปิด: {n} รายการ", done="ปกปิดแล้ว: {n} รายการ",
        added="บันทึกลายนิ้วมือแล้ว", forgotten="ลบลายนิ้วมือแล้ว",
        not_found="ไม่มีลายนิ้วมือของค่านี้", bad_length="ความยาวต้องอยู่ระหว่าง 4 ถึง 8192 ตัวอักษร",
        prompt_value="ค่า (ซ่อนอยู่): ",
        stdin_value="กำลังอ่านค่าจากอินพุตมาตรฐาน: หากเป็นเทอร์มินัล ค่าจะมองเห็นได้",
        no_arguments="คำสั่งนี้ไม่รับอาร์กิวเมนต์: คำสั่งจะถามค่าเพื่อไม่ให้ค่าอยู่ในประวัติเชลล์ ยังไม่ได้บันทึกสิ่งใด",
        reset_confirm="การดำเนินการนี้จะลบกุญแจและลายนิ้วมือของคอมพิวเตอร์เครื่องนี้ และจะไม่จดจำข้อมูลลับที่ให้ไว้แล้วอีก บันทึกจะไม่ถูกแก้ไข เรียกใช้อีกครั้งพร้อม --yes เพื่อดำเนินการต่อ",
        reset_done="ลบกุญแจ ลายนิ้วมือ และสถานะแล้ว",
        reset_shared="ไม่ลบไฟล์ที่ใช้ร่วมกัน เพราะคอมพิวเตอร์เครื่องอื่นใช้อยู่: {path} หากต้องการใช้ร่วมกันต่อ ให้คัดลอก key.bin จากคอมพิวเตอร์เครื่องอื่นอีกครั้ง",
        no_store="ไม่สามารถบันทึกลายนิ้วมือ: {problem}", no_read="ไม่สามารถอ่านลายนิ้วมือ: {problem}",
        warn_earlier="คำเตือน: {problem}: ไม่ได้ค้นหาข้อมูลลับที่ให้ไว้ก่อนหน้า",
        warn_damaged="คำเตือน: แยกที่เก็บลายนิ้วมือที่เสียหาย {n} รายการไว้ใน {path}: จะไม่ค้นหาข้อมูลลับที่ให้ไว้ก่อนหน้านั้นอีก",
        warn_folder="คำเตือน: โฟลเดอร์ใน CLAUDEPASSREDACTOR_DIRS ถูกปฏิเสธหรือไม่มีอยู่",
        warn_shared="คำเตือน: ลายนิ้วมือที่ใช้ร่วมกัน: {problem}",
        warn_shared_forget="คำเตือน: ลายนิ้วมือที่ใช้ร่วมกัน: {problem} คอมพิวเตอร์เครื่องอื่นยังเก็บค่านี้ไว้",
        cannot_read="อ่านไม่ได้: {path}", cannot_review="ตรวจสอบไม่ได้: {path}",
        lines="บรรทัด {lines}", os_error="ข้อผิดพลาด: {detail}"),
    "hi": dict(
        detected="🔒 इस संदेश में संभावित गोपनीय जानकारी: {n}। जो मेमोरी नोट में पहुँचेगी उसे {tag} से बदल दिया जाएगा।",
        redacted="🔒 मेमोरी में {tag} से बदली गई गोपनीय जानकारी: {n} ({files})।",
        attention="⚠️ मेमोरी रेडैक्टर पर ध्यान देने की ज़रूरत है। चलाएँ: claudepassredactor.py status",
        key_problem="⚠️ मेमोरी रेडैक्टर: कुंजी में समस्या है, याद रखी गई गोपनीय जानकारी नहीं खोजी जा रही। चलाएँ: claudepassredactor.py status",
        nothing="छिपाने के लिए कुछ नहीं है।", would="छिपाया जाएगा: {n}", done="छिपाया गया: {n}",
        added="फ़िंगरप्रिंट सहेजा गया।", forgotten="फ़िंगरप्रिंट हटाया गया।",
        not_found="इस मान का कोई फ़िंगरप्रिंट नहीं है।", bad_length="लंबाई 4 से 8192 वर्णों के बीच होनी चाहिए।",
        prompt_value="मान (छिपा हुआ): ",
        stdin_value="मान मानक इनपुट से पढ़ा जा रहा है: यदि यह टर्मिनल है, तो वह दिखाई देगा।",
        no_arguments="यह कमांड कोई आर्ग्युमेंट नहीं लेता: यह मान पूछता है, ताकि वह शेल इतिहास में न रहे। कुछ भी सहेजा नहीं गया।",
        reset_confirm="इससे इस कंप्यूटर की कुंजी और फ़िंगरप्रिंट हट जाएँगे, और पहले दी गई गोपनीय जानकारी याद नहीं रहेगी। नोट नहीं बदले जाते। आगे बढ़ने के लिए --yes के साथ दोबारा चलाएँ।",
        reset_done="कुंजी, फ़िंगरप्रिंट और स्थिति हटा दिए गए।",
        reset_shared="साझा फ़ाइल नहीं हटाई जाती, क्योंकि अन्य कंप्यूटर उसका उपयोग करते हैं: {path}। साझा करना जारी रखने के लिए किसी अन्य कंप्यूटर से key.bin फिर से कॉपी करें।",
        no_store="फ़िंगरप्रिंट सहेजे नहीं जा सकते: {problem}", no_read="फ़िंगरप्रिंट पढ़े नहीं जा सकते: {problem}",
        warn_earlier="चेतावनी: {problem}: पहले दी गई गोपनीय जानकारी नहीं खोजी जा रही",
        warn_damaged="चेतावनी: {n} क्षतिग्रस्त फ़िंगरप्रिंट स्टोर {path} में अलग रखे गए: उससे पहले दी गई गोपनीय जानकारी अब नहीं खोजी जाती",
        warn_folder="चेतावनी: CLAUDEPASSREDACTOR_DIRS का एक फ़ोल्डर अस्वीकार हुआ या मौजूद नहीं है",
        warn_shared="चेतावनी: साझा फ़िंगरप्रिंट: {problem}",
        warn_shared_forget="चेतावनी: साझा फ़िंगरप्रिंट: {problem}; अन्य कंप्यूटरों पर यह मान बना रहेगा",
        cannot_read="पढ़ा नहीं जा सका: {path}", cannot_review="जाँचा नहीं जा सका: {path}",
        lines="पंक्तियाँ {lines}", os_error="त्रुटि: {detail}"),
}


def _normalise_language(raw):
    token = raw.split(":")[0].split(".")[0].split("@")[0].replace("_", "-").lower()
    if token in ("", "c", "posix"):
        return None
    if token.startswith("zh"):
        return "zh-CN"
    base = token.split("-")[0]
    return base if base in MESSAGES else None


def ui_language(env=None):
    env = os.environ if env is None else env
    for var in ("CLAUDEPASSREDACTOR_LANG", "LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        code = _normalise_language(env.get(var) or "")
        if code:
            return code
    if os.name == "nt":
        try:
            import ctypes
            buffer = ctypes.create_unicode_buffer(85)
            if ctypes.windll.kernel32.GetUserDefaultLocaleName(buffer, 85):
                return _normalise_language(buffer.value) or "en"
        except (OSError, AttributeError):
            pass
    return "en"


def message(key, lang=None, **values):
    return MESSAGES[lang or ui_language()][key].format(tag=TAG, **values)


# --- hooks ---------------------------------------------------------------------------------

def _attention(state, problems, report):
    """Which warning to show, if any. Each distinct problem is shown once, not on every message."""
    signature = "|".join(sorted(set(problems)) + sorted({os.path.basename(p) for p in report.failed}))
    if not signature:
        state.pop("warned", None)
        return None
    if state.get("warned") == signature:
        return None
    state["warned"] = signature
    return "key_problem" if any(p.startswith("key_") for p in problems) else "attention"


def _summary(report):
    names = ", ".join(sorted({os.path.basename(c["path"]) for c in report.changed}))
    return report.total, names


def _save_state_if_changed(paths, state, original):
    if state != original:
        try:
            _write_private_json(paths.state, state)
        except OSError as exc:
            log_event(paths, f"could not save the state errno={exc.errno}")


def _output(event, system=None, context=None):
    out = {}
    if system:
        out["systemMessage"] = system
    if context and event in ("UserPromptSubmit", "PostToolUse", "SessionStart"):
        out["hookSpecificOutput"] = {"hookEventName": event, "additionalContext": context}
    if out:
        sys.stdout.write(json.dumps(out, ensure_ascii=True) + "\n")   # ASCII: no console can choke on it


def hook_prompt(paths, payload):
    deadline = time.monotonic() + HOOK_BUDGET
    text = payload.get("prompt")
    candidates = prompt_candidates(nfc(text), deadline) if isinstance(text, str) else []
    roots = memory_roots(paths)
    with _Lock(paths) as lock:
        key, key_problem = load_key(paths)
        entries, store_problem = load_fingerprints(paths)
        problems = [p for p in (key_problem, store_problem, roots_problem(paths, roots)) if p]
        state = load_state(paths)
        original = json.loads(json.dumps(state))
        fresh_index = None
        if entries is not None:
            try:
                absorb_pending(paths, lock, entries)
            except OSError as exc:
                log_event(paths, f"could not take in pending fingerprints errno={exc.errno}")
        shared_problem = _try_sync_shared(paths, lock, key, entries)
        if shared_problem:
            problems.append(shared_problem)
        can_remember = key is not None and entries is not None
        if candidates and can_remember:
            new = [e for value, strength in candidates for e in _entries_for(key, value, strength)]
            up_to_date = state.get("fingerprints") == _store_signature(paths)
            try:
                if remember(paths, lock, entries, new) and up_to_date:
                    fresh_index = build_index(new)
            except OSError as exc:
                problems.append("store_unwritable")
                log_event(paths, f"could not save fingerprints errno={exc.errno}")
            if not shared_problem:
                shared_problem = _try_sync_shared(paths, lock, key, entries, revived={e["h"] for e in new})
                if shared_problem:
                    problems.append(shared_problem)
        report = review(paths, roots, key, build_index(entries), state, deadline=deadline, fresh_index=fresh_index)
        warning = _attention(state, problems, report)
        _save_state_if_changed(paths, state, original)
    system, context = [], None
    if candidates:
        context = (f"(memory redactor) This message appears to contain {len(candidates)} secret(s). Do not "
                   f"store them in memory; if they reach a memory note they will be replaced with {TAG}.")
    if report.changed:
        total, names = _summary(report)
        system.append(message("redacted", n=total, files=names))
    elif candidates and can_remember:
        system.append(message("detected", n=len(candidates)))
    if candidates and not can_remember:  # never say it will be masked when it would not be
        warning = "key_problem" if key is None else "attention"
    if warning:
        system.append(message(warning))
    _output(payload.get("hook_event_name") or "UserPromptSubmit", " ".join(system), context)


def hook_memory(paths, payload):
    deadline = time.monotonic() + HOOK_BUDGET
    tool_input = payload.get("tool_input")
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    named = [tool_input[k] for k in ("file_path", "notebook_path") if isinstance(tool_input.get(k), str)]
    roots = memory_roots(paths)
    targets = None
    if named:                            # a file tool: only that file, and only if it is a note
        targets = [t for t in (resolve_target(r, payload.get("cwd"), roots) for r in named) if t]
        if not targets:
            return
    with _Lock(paths) as lock:
        key, key_problem = load_key(paths)
        entries, store_problem = load_fingerprints(paths)
        shared_problem = _try_sync_shared(paths, lock, key, entries)
        state = load_state(paths)
        original = json.loads(json.dumps(state))
        report = review(paths, roots, key, build_index(entries), state, targets=targets, deadline=deadline)
        problems = [p for p in (key_problem, store_problem, shared_problem, roots_problem(paths, roots)) if p]
        warning = _attention(state, problems, report)
        _save_state_if_changed(paths, state, original)
    system, context = [], None
    if report.changed:
        total, names = _summary(report)
        system.append(message("redacted", n=total, files=names))
        context = (f"(memory redactor) {total} secret(s) were replaced with {TAG} in {names}. The file has "
                   f"changed on disk: read it again before editing it, and do not write the secret back.")
    if warning:
        system.append(message(warning))
    _output(payload.get("hook_event_name") or "PostToolUse", " ".join(system), context)


def run_hook(mode, paths=None):
    """A hook always exits 0 and prints only fixed text, counts and file names. It must never
    get in the way of Claude Code; failures are logged and shown as a generic warning."""
    try:
        paths = paths or Paths()
        try:
            payload = json.loads(sys.stdin.buffer.read().decode("utf-8", "surrogatepass") or "{}")
        except ValueError:
            payload = {}
        if not isinstance(payload, dict):
            payload = {}
        (hook_prompt if mode == "prompt" else hook_memory)(paths, payload)
    except Exception as exc:
        if paths:
            log_exception(paths, exc)
        try:
            _output("", message("attention"))
        except Exception:
            pass
    return 0


# --- command line ---------------------------------------------------------------------------

def _read_secret():
    """Whitespace at the ends is not part of a value: a value starting with it could never match."""
    if sys.stdin.isatty():
        import getpass
        return getpass.getpass(message("prompt_value")).strip()
    print(message("stdin_value"), file=sys.stderr)
    return sys.stdin.readline().strip()


def _store_warnings(paths, key_problem, store_problem, lang=None):
    """Things that make a clean result misleading. Printed by scan, redact and status."""
    lines = [message("warn_earlier", lang, problem=problem) for problem in (key_problem, store_problem) if problem]
    try:
        damaged = [n for n in os.listdir(paths.data) if ".corrupt-" in n]
    except OSError:
        damaged = []
    if damaged:
        lines.append(message("warn_damaged", lang, n=len(damaged), path=paths.data))
    return lines


def _mask_line(item, start_of_line, end_of_line):
    text = item["text"]
    spans = [s for s in item["spans"] if s[1] > start_of_line and s[0] < end_of_line]
    parts, pos = [], start_of_line
    for start, end, kinds in spans:
        parts.append(text[pos:max(start, pos)])
        parts.append(f"<{'+'.join(sorted(kinds))}>")
        pos = min(end, end_of_line)
    parts.append(text[pos:end_of_line])
    return "".join(parts).strip()


def cli_scan(paths, args):
    key, key_problem = load_key(paths, create=False)
    entries, store_problem = load_fingerprints(paths, quarantine=False)
    roots = memory_roots(paths)
    report = review(paths, roots, key, build_index(entries), {"files": {}}, full=True,
                    dry_run=True, include_hidden=args.all, keep_text=args.context)
    warnings = _store_warnings(paths, key_problem, store_problem)
    if roots_problem(paths, roots):
        warnings.append(message("warn_folder"))
    for item in report.changed:
        print(f"{item['path']}: {item['count']} ({', '.join(item['kinds'])}), {message('lines', lines=item['lines'])}")
        if args.context:
            text, seen = item["text"], set()
            for start, _end, _kinds in item["spans"]:
                a = text.rfind("\n", 0, start) + 1
                if a in seen:
                    continue
                seen.add(a)
                b = text.find("\n", start)
                b = len(text) if b < 0 else b
                print(f"    {text.count(chr(10), 0, start) + 1}: {_mask_line(item, a, b)}")
    for path in report.failed:
        print(message("cannot_read", path=path))
    print(message("would", n=report.total) if report.total else message("nothing"))
    print("\n".join(warnings), end="\n" if warnings else "")
    return 2 if report.failed or warnings else 1 if report.total else 0


def cli_redact(paths, args):
    roots = memory_roots(paths)
    with _Lock(paths) as lock:
        key, key_problem = load_key(paths)
        entries, store_problem = load_fingerprints(paths)
        if entries is not None:
            absorb_pending(paths, lock, entries)
        shared_problem = _try_sync_shared(paths, lock, key, entries)
        state = load_state(paths)
        report = review(paths, roots, key, build_index(entries), state, full=True, include_hidden=args.all)
        _write_private_json(paths.state, state)
    warnings = _store_warnings(paths, key_problem, store_problem)
    if shared_problem:
        warnings.append(message("warn_shared", problem=shared_problem))
    if roots_problem(paths, roots):
        warnings.append(message("warn_folder"))
    for item in report.changed:
        print(f"{item['path']}: {item['count']} ({', '.join(item['kinds'])})")
    for path in report.failed:
        print(message("cannot_review", path=path))
    print(message("done", n=report.total) if report.total else message("nothing"))
    print("\n".join(warnings), end="\n" if warnings else "")
    return 2 if report.failed or warnings else 0


def _user_hooks(paths):
    try:
        with open(os.path.join(paths.config, "settings.json"), encoding="utf-8-sig") as f:
            hooks = json.load(f).get("hooks", {})
    except (OSError, ValueError, AttributeError):
        return {}
    return hooks if isinstance(hooks, dict) else {}


def _hook_registered(paths):
    hooks = _user_hooks(paths)
    return "claudepassredactor" in json.dumps(hooks.get("UserPromptSubmit", "")) and \
        "claudepassredactor" in json.dumps(hooks.get("PostToolUse", ""))


_HOOK_SCRIPT = re.compile(r""""[^"]*claudepassredactor\.py"|'[^']*claudepassredactor\.py'|\S*claudepassredactor\.py""")


def _registered_commands(paths):
    """(command, path of the script as written, shell) of every hook that runs this tool."""
    found = []
    for groups in _user_hooks(paths).values():
        for group in groups if isinstance(groups, list) else ():
            entries = group.get("hooks") if isinstance(group, dict) else None
            for entry in entries if isinstance(entries, list) else ():
                command = entry.get("command") if isinstance(entry, dict) else None
                script = _HOOK_SCRIPT.search(command) if isinstance(command, str) else None
                if script:
                    found.append((command, script.group().strip("\"'"), entry.get("shell")))
    return found


def _script_exists(script):
    """Whether a path written in a hook command names a file, reading it as the shell would."""
    path = os.path.expandvars(os.path.expanduser(script))
    if os.name == "nt":                  # Git Bash calls C:/x /c/x
        path = re.sub(r"^/([A-Za-z])(?=/)", r"\1:", path)
    return os.path.isabs(path) and os.path.isfile(path)


def _hook_warnings(paths):
    """A wrong path is worse than it looks: Python exits with code 2, and Claude Code takes that
    from a UserPromptSubmit hook as a refusal of the message. Only an explicit PowerShell hook
    can use backslashes: Git Bash, the default on Windows, removes them."""
    lines = set()
    for command, script, shell in _registered_commands(paths):
        if "\\" in command and shell != "powershell":
            lines.add(f"warning: a hook command has backslashes, which break it; use forward slashes: {command}")
        elif not _script_exists(script):
            lines.add(f"warning: a hook command points to a file that does not exist: {script}")
    return sorted(lines)


def _windows_ace_count(path):
    import subprocess
    icacls = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "icacls.exe")
    try:
        out = subprocess.run([icacls, path], capture_output=True, timeout=10,
                             creationflags=subprocess.CREATE_NO_WINDOW).stdout
        return out.decode("utf-8", "ignore").count(":(")
    except (OSError, subprocess.SubprocessError):
        return None


def _shared_status(paths, key):
    try:
        items, _forgotten, check = _read_shared(paths.shared)
    except FileNotFoundError:
        return "not created yet"
    except (OSError, ValueError, KeyError, TypeError):
        return "warning: could not be read, and it will not be replaced"
    if key is not None and check != _key_check(key):
        return "warning: made with another key; copy key.bin from the other computer"
    return str(len(items))


def cli_status(paths, _args):
    roots = memory_roots(paths)
    key, key_problem = load_key(paths, create=False)
    entries, store_problem = load_fingerprints(paths, quarantine=False)
    notes = sum(1 for _ in iter_notes(roots))
    print(f"claudepassredactor {__version__}")
    print(f"hooks registered in user settings: {'yes' if _hook_registered(paths) else 'no'}")
    hook_warnings = _hook_warnings(paths)
    print("\n".join(hook_warnings), end="\n" if hook_warnings else "")
    print(f"data folder: {paths.data}")
    if os.path.isdir(paths.data):
        opened = (_windows_ace_count(paths.data) != 1 if os.name == "nt"
                  else stat.S_IMODE(os.stat(paths.data).st_mode) & 0o077)
        if opened:
            print("data folder: warning: it is not private to your user, so others may read its fingerprints")
    print(f"memory folders: {len(roots)}, notes: {notes}")
    for root in roots:
        print(f"  {root}")
    refused = roots_problem(paths, roots)
    if refused:
        print(message("warn_folder", "en"))
    key_status = key_problem or ("ok" if key else "not created yet")
    if key and os.name == "nt":
        aces = _windows_ace_count(paths.key)
        if aces != 1:
            key_status += f" (warning: {aces} access rules, expected 1)"
    elif key and stat.S_IMODE(os.lstat(paths.key).st_mode) & 0o077:
        key_status += " (warning: readable by others)"
    print(f"key: {key_status}")
    print(f"fingerprints: {store_problem or len(entries or [])}")
    if paths.shared_refused:
        print("warning: CLAUDEPASSREDACTOR_SHARED must be an absolute path; it is being ignored")
    if paths.shared:
        print(f"shared fingerprints: {_shared_status(paths, key)} ({paths.shared})")
    if any(_inside(root, os.path.realpath(paths.key)) for root in roots):
        print("warning: the key is inside a memory folder; move it out with CLAUDEPASSREDACTOR_DATA")
    warnings = _store_warnings(paths, key_problem, store_problem, lang="en")
    print("\n".join(warnings), end="\n" if warnings else "")
    try:
        with open(paths.log, encoding="utf-8", errors="replace") as f:
            errors = sum(1 for line in f if any(w in line for w in (" ERROR ", "could not", "ran out", "was corrupt")))
    except OSError:
        errors = 0
    print(f"errors in the log: {errors}")
    return 2 if warnings or refused or hook_warnings else 0


def cli_add(paths, _args):
    value = nfc(_read_secret())
    if not 4 <= len(value) <= MAX_VALUE:
        print(message("bad_length"))
        return 2
    with _Lock(paths) as lock:
        key, problem = load_key(paths)
        entries, store_problem = load_fingerprints(paths)
        if not key or entries is None:
            print(message("no_store", problem=problem or store_problem))
            return 2
        absorb_pending(paths, lock, entries)
        new = _entries_for(key, value, "strong")
        merge_entries(entries, new)
        save_fingerprints(paths, entries)
        shared_problem = _try_sync_shared(paths, lock, key, entries, revived={e["h"] for e in new})
        state = load_state(paths)
        report = review(paths, memory_roots(paths), key, build_index(entries), state)
        _write_private_json(paths.state, state)
    if shared_problem:
        print(message("warn_shared", problem=shared_problem))
    print(message("added"))
    print(message("done", n=report.total))
    return 0


def cli_forget(paths, _args):
    value = nfc(_read_secret())
    with _Lock(paths) as lock:
        key, problem = load_key(paths, create=False)
        entries, store_problem = load_fingerprints(paths)
        if not key or entries is None:
            print(message("no_read", problem=problem or store_problem or "no key"))
            return 2
        absorb_pending(paths, lock, entries)
        shared_problem = _try_sync_shared(paths, lock, key, entries)
        # A message records "Hunter2!" in both forms, with and without the last character.
        base = value.rstrip("!?")
        digests = {fingerprint(key, form) for form in (value, base, base + "!", base + "?")}
        kept = [e for e in entries if e["h"] not in digests]
        if len(kept) == len(entries):
            print(message("not_found"))
            return 1
        save_fingerprints(paths, kept)
        shared_problem = shared_problem or _try_sync_shared(paths, lock, key, kept, forgotten=digests)
    if shared_problem:
        print(message("warn_shared_forget", problem=shared_problem))
    print(message("forgotten"))
    return 0


def cli_reset(paths, args):
    keeps_shared = paths.shared and os.path.exists(paths.shared)
    if not args.yes:
        print(message("reset_confirm"))
        if keeps_shared:
            print(message("reset_shared", path=paths.shared))
        return 2
    with _Lock(paths):
        try:
            extra = [os.path.join(paths.data, n) for n in os.listdir(paths.data)
                     if ".corrupt-" in n or n.startswith(_PENDING_PREFIX)]
        except OSError:
            extra = []
        for path in [paths.key, paths.fingerprints, paths.state] + extra:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass
    print(message("reset_done"))
    if keeps_shared:
        print(message("reset_shared", path=paths.shared))
    return 0


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    wants_help = any(arg in ("-h", "--help") for arg in argv[1:])
    if argv[:1] in (["prompt"], ["memory"]) and not wants_help:
        return run_hook(argv[0])
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="backslashreplace")
    if argv[:1] in (["add"], ["forget"]) and argv[1:] and not wants_help:
        print(message("no_arguments"), file=sys.stderr)
        return 2
    import argparse
    parser = argparse.ArgumentParser(prog="claudepassredactor.py", description=__doc__.split("\n")[0])
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("prompt", help="hook mode for UserPromptSubmit (JSON on stdin)")
    commands.add_parser("memory", help="hook mode for PostToolUse (JSON on stdin)")
    scan = commands.add_parser("scan", help="list what would be replaced; changes nothing")
    scan.add_argument("--context", action="store_true", help="also print each line with every match masked")
    scan.add_argument("--all", action="store_true", help="include hidden folders, except .git")
    redact = commands.add_parser("redact", help="review every note now")
    redact.add_argument("--all", action="store_true", help="include hidden folders, except .git")
    commands.add_parser("status", help="show folders, key and fingerprint health, hook paths")
    commands.add_parser("add", help="remember a secret, typed at a hidden prompt")
    commands.add_parser("forget", help="stop looking for a secret, typed at a hidden prompt")
    reset = commands.add_parser("reset", help="delete the key and this computer's fingerprints, not the shared file")
    reset.add_argument("--yes", action="store_true", help="go ahead; without it, only explains what would be deleted")
    args = parser.parse_args(argv)
    handler = {"scan": cli_scan, "redact": cli_redact, "status": cli_status, "add": cli_add,
               "forget": cli_forget, "reset": cli_reset}[args.command]
    try:
        return handler(Paths(), args)
    except OSError as exc:               # no message or file contents: type and number only
        print(message("os_error", detail=f"{type(exc).__name__} errno={exc.errno}"))
        return 2


if __name__ == "__main__":
    sys.exit(main())
