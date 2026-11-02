"""Test sentences for each of the 15 languages. Every secret here is invented.

secrets      a user's message and the one value that must be recognised in it
not_secrets  ordinary sentences in which nothing may be recognised (typical false positives)
notes        a note and the labelled value a review must replace, with no earlier fingerprint
intact       ordinary prose a review must leave byte for byte
weak         a PIN given in a message, a note that mentions it next to a keyword, and a note
             where the same digits mean something else
"""

CASES = {
    "en": dict(
        secrets=[
            ("the wifi password is Hunter-2024x", "Hunter-2024x"),
            ("password: Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("The password for the office router is Zebra-Lamp-77.", "Zebra-Lamp-77"),
            ("my PIN is 4471", "4471"),
            ("I changed the password to Mango-Tree-42", "Mango-Tree-42"),
            ("the password to Server2024 is Cedar-North-42", "Cedar-North-42"),
            ("the api key is Ab12Cd34Ef56Gh78", "Ab12Cd34Ef56Gh78"),
            ("use this token: Qw3rTy-Uiop-9876", "Qw3rTy-Uiop-9876"),
            ('"password": "Json-Value-31"', "Json-Value-31"),
            ("DB_PASSWORD=Under-Score-55", "Under-Score-55"),
            ("passphrase = Long-Phrase-2024", "Long-Phrase-2024"),
        ],
        not_secrets=[
            "The password is incorrect.",
            "the password is required",
            "The password must have at least 8 characters",
            "password manager: Bitwarden7",
            "password: <your-password>",
            "password=${DB_PASSWORD}",
            "the password reset link: https://example.com/reset",
            "password policy: Min8-Chars",
            "1Password: Vault-2024x",
            "The compass: N45-E012-W7",
            "the port mapping: Foo-Bar-123",
            "bypass: v2-beta-2024",
            "pin 13 is HIGH",
            "pinned: abc12345",
            "token count: 12000",
            "secret sauce: Recipe-2024",
            "the password is well-known",
            "the password is 10.0.0.5",
            "The password was changed on 2024-03-01",
        ],
        notes=[
            ("Router notes. The wifi password is Hunter-2024x, ask Ana before changing it.\n", "Hunter-2024x"),
            ("| service | password |\n| wiki | x |\n| password | Table-Cell-99 |\n", "Table-Cell-99"),
            ("**Password:** Bold-Label-2024 for the NAS\n", "Bold-Label-2024"),
        ],
        intact=("Remember that the password is required on first login. The password manager is open source.\n"
                "Port mapping uses pin 13, and the key point is speed. Version 2.4.1 shipped on 2024-03-01\n"
                "at 10.0.0.5, see notes.txt. Tokens are counted per request; the secret sauce is caching.\n"),
        weak=("the alarm PIN is 8123", "The alarm pin is 8123, do not share it.\n",
              "Room 8123 is on the left. Ticket 18123 is closed.\n"),
    ),
    "es": dict(
        secrets=[
            ("la clave del garaje es Garaje-Norte-01", "Garaje-Norte-01"),
            ("contraseña: Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("La contraseña del wifi de la oficina es Cebra-Lampara-77.", "Cebra-Lampara-77"),
            ("el pin es 4471", "4471"),
            ("he cambiado la contraseña a Mango-Arbol-42", "Mango-Arbol-42"),
            ("contrasena: Sin-Tilde-2024", "Sin-Tilde-2024"),
            ("el código de acceso es 998877", "998877"),
            ("el token es Qw3rTy-Uiop-9876", "Qw3rTy-Uiop-9876"),
        ],
        not_secrets=[
            "La contraseña es incorrecta.",
            "contraseña incorrecta: inténtalo de nuevo",
            "la contraseña debe tener 8 caracteres",
            "gestor de contraseñas: Bitwarden7",
            "contraseña: ${DB_PASS}",
            "la clave es la constancia",
            "palabra clave: Python3-Async",
            "clave pública: ssh-ed25519AAAA1234",
            "el mapa de pines es A1-B2-C3",
            "la opinión es clara",
            "el código es 28001",
            "Contraseña: ver el gestor (bóveda)",
        ],
        notes=[
            ("Notas del router. La contraseña del wifi es Cebra-Lampara-77, pregunta antes de cambiarla.\n",
             "Cebra-Lampara-77"),
            ("Contraseña del NAS: Olivo-Viento-2024\n", "Olivo-Viento-2024"),
        ],
        intact=("Recuerda que la contraseña es obligatoria al entrar. El gestor de contraseñas es libre.\n"
                "La clave es la constancia y el punto clave es la velocidad. La versión 2.4.1 salió el\n"
                "2024-03-01. El código es abierto y el pin 13 del conector no se usa. Ver notas.txt.\n"),
        weak=("el pin de la alarma es 8123", "El pin de la alarma es 8123, no lo compartas.\n",
              "La sala 8123 está a la izquierda. El ticket 18123 está cerrado.\n"),
    ),
    "pt": dict(
        secrets=[
            ("a senha do wifi é Zebra-Lampada-77", "Zebra-Lampada-77"),
            ("senha: Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("A palavra-passe do router é Cedro-Norte-42.", "Cedro-Norte-42"),
            ("o PIN é 4471", "4471"),
            ("mudei a senha para Manga-Arvore-42", "Manga-Arvore-42"),
            ("a chave da API é Ab12Cd34Ef56Gh78", "Ab12Cd34Ef56Gh78"),
        ],
        not_secrets=[
            "A senha está incorreta.",
            "a senha é obrigatória",
            "a senha deve ter 8 caracteres",
            "gerenciador de senhas: Bitwarden7",
            "senha: <sua-senha>",
            "palavra-chave: Python3-Async",
            "chave pública: ssh-ed25519AAAA1234",
            "a opinião é clara",
        ],
        notes=[
            ("Notas do router. A senha do wifi é Zebra-Lampada-77, pergunte antes de mudar.\n", "Zebra-Lampada-77"),
            ("Senha do NAS: Oliveira-Vento-2024\n", "Oliveira-Vento-2024"),
        ],
        intact=("Lembre-se de que a senha é obrigatória na entrada. O gestor de senhas é livre.\n"
                "A chave é a constância e a palavra-chave é velocidade. A versão 2.4.1 saiu em 2024-03-01.\n"
                "O código é aberto e o pino 13 não é usado. Ver notas.txt.\n"),
        weak=("o PIN do alarme é 8123", "O PIN do alarme é 8123, não partilhe.\n",
              "A sala 8123 fica à esquerda. O pedido 18123 está fechado.\n"),
    ),
    "fr": dict(
        secrets=[
            ("le mot de passe du wifi est Zebre-Lampe-77", "Zebre-Lampe-77"),
            ("mot de passe : Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("Le mot de passe du routeur, c'est Cedre-Nord-42.", "Cedre-Nord-42"),
            ("le code PIN est 4471", "4471"),
            ("mdp = Mangue-Arbre-42", "Mangue-Arbre-42"),
            ("j'ai changé le mot de passe en Olive-Vent-2024", "Olive-Vent-2024"),
            ("la clé API est Ab12Cd34Ef56Gh78", "Ab12Cd34Ef56Gh78"),
            ("mot de passe : « Guillemet-2024 »", "Guillemet-2024"),
        ],
        not_secrets=[
            "Le mot de passe est incorrect.",
            "le mot de passe doit contenir 8 caractères",
            "gestionnaire de mots de passe : Bitwarden7",
            "mot de passe : <votre-mot-de-passe>",
            "clé publique : ssh-ed25519AAAA1234",
            "mot-clé : Python3-Async",
            "mot de passe oublié : Aide-2024x",
            "la clé de voûte est Rome-2024x",
            "Le terme « mot de passe » est d'origine militaire.",
            "Le mot de passe sert alors à chiffrer/déchiffrer la clé.",
            "ce mot de passe apparaîtra en clair à l'attaquant",
            "le mot de passe (c'est-à-dire la question)",
        ],
        notes=[
            ("Notes du routeur. Le mot de passe du wifi est Zebre-Lampe-77, demande avant de le changer.\n",
             "Zebre-Lampe-77"),
            ("Mot de passe du NAS : Olive-Vent-2024\n", "Olive-Vent-2024"),
        ],
        intact=("Le mot de passe est obligatoire à la connexion. Le gestionnaire de mots de passe est libre.\n"
                "La clé de voûte est la constance et le mot-clé est vitesse. La version 2.4.1 est sortie le\n"
                "2024-03-01. Le code est ouvert et la broche 13 ne sert pas. Voir notes.txt.\n"),
        weak=("le code PIN de l'alarme est 8123", "Le code PIN de l'alarme est 8123, ne le partage pas.\n",
              "La salle 8123 est à gauche. Le ticket 18123 est fermé.\n"),
    ),
    "de": dict(
        secrets=[
            ("das WLAN-Passwort lautet Zebra-Lampe-77", "Zebra-Lampe-77"),
            ("Passwort: Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("Das Passwort für den Router ist Zeder-Nord-42.", "Zeder-Nord-42"),
            ("Die PIN ist 4471", "4471"),
            ("Ich habe das Passwort auf Mango-Baum-42 geändert", "Mango-Baum-42"),
            ("Kennwort = Olive-Wind-2024", "Olive-Wind-2024"),
            ("Routerpasswort: Birke-Ost-2024", "Birke-Ost-2024"),
        ],
        not_secrets=[
            "Das Passwort ist falsch.",
            "Das Passwort muss 8 Zeichen lang sein",
            "Passwortmanager: Bitwarden7",
            "Passwort-Manager: Bitwarden7",
            "Passwort: <dein-passwort>",
            "öffentlicher Schlüssel: ssh-ed25519AAAA1234",
            "Schlüsselwort: Python3-Async",
            "Der Schlüssel ist im Schrank",
        ],
        notes=[
            ("Router-Notizen. Das WLAN-Passwort lautet Zebra-Lampe-77, bitte vorher fragen.\n", "Zebra-Lampe-77"),
            ("Passwort des NAS: Olive-Wind-2024\n", "Olive-Wind-2024"),
        ],
        intact=("Das Passwort ist beim ersten Login erforderlich. Der Passwort-Manager ist quelloffen.\n"
                "Der Schlüssel liegt im Schrank und das Schlüsselwort ist Tempo. Version 2.4.1 erschien am\n"
                "2024-03-01. Der Code ist offen und Pin 13 wird nicht benutzt. Siehe notizen.txt.\n"),
        weak=("die PIN der Alarmanlage ist 8123", "Die PIN der Alarmanlage ist 8123, nicht weitergeben.\n",
              "Raum 8123 ist links. Ticket 18123 ist geschlossen.\n"),
    ),
    "it": dict(
        secrets=[
            ("la password del wifi è Zebra-Lampada-77", "Zebra-Lampada-77"),
            ("password: Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("La password del router è Cedro-Nord-42.", "Cedro-Nord-42"),
            ("il PIN è 4471", "4471"),
            ("ho cambiato la password in Mango-Albero-42", "Mango-Albero-42"),
            ("la chiave API è Ab12Cd34Ef56Gh78", "Ab12Cd34Ef56Gh78"),
            ("parola d'ordine: Olivo-Vento-2024", "Olivo-Vento-2024"),
        ],
        not_secrets=[
            "La password è sbagliata.",
            "password errata: riprova",
            "la password deve avere 8 caratteri",
            "gestore di password: Bitwarden7",
            "password: <la-tua-password>",
            "chiave pubblica: ssh-ed25519AAAA1234",
            "parola chiave: Python3-Async",
            "la chiave di violino è Sol-2024x",
        ],
        notes=[
            ("Note del router. La password del wifi è Zebra-Lampada-77, chiedi prima di cambiarla.\n",
             "Zebra-Lampada-77"),
            ("Password del NAS: Olivo-Vento-2024\n", "Olivo-Vento-2024"),
        ],
        intact=("La password è obbligatoria al primo accesso. Il gestore di password è libero.\n"
                "La chiave è la costanza e la parola chiave è velocità. La versione 2.4.1 è uscita il\n"
                "2024-03-01. Il codice è aperto e il pin 13 non si usa. Vedi note.txt.\n"),
        weak=("il PIN dell'allarme è 8123", "Il PIN dell'allarme è 8123, non condividerlo.\n",
              "La sala 8123 è a sinistra. Il ticket 18123 è chiuso.\n"),
    ),
    "nl": dict(
        secrets=[
            ("het wifi-wachtwoord is Zebra-Lamp-77", "Zebra-Lamp-77"),
            ("wachtwoord: Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("Het wachtwoord van de router is Ceder-Noord-42.", "Ceder-Noord-42"),
            ("de pincode is 4471", "4471"),
            ("ik heb het wachtwoord gewijzigd naar Mango-Boom-42", "Mango-Boom-42"),
            ("beheerderswachtwoord = Olijf-Wind-2024", "Olijf-Wind-2024"),
        ],
        not_secrets=[
            "Het wachtwoord is onjuist.",
            "het wachtwoord moet 8 tekens bevatten",
            "wachtwoordmanager: Bitwarden7",
            "wachtwoord: <jouw-wachtwoord>",
            "sleutelwoord: Python3-Async",
            "openbare sleutel: ssh-ed25519AAAA1234",
        ],
        notes=[
            ("Routernotities. Het wifi-wachtwoord is Zebra-Lamp-77, vraag het eerst.\n", "Zebra-Lamp-77"),
            ("Wachtwoord van de NAS: Olijf-Wind-2024\n", "Olijf-Wind-2024"),
        ],
        intact=("Het wachtwoord is verplicht bij de eerste keer. De wachtwoordmanager is open source.\n"
                "De sleutel ligt in de kast en het sleutelwoord is snelheid. Versie 2.4.1 kwam uit op\n"
                "2024-03-01. De code is open en pin 13 wordt niet gebruikt. Zie notities.txt.\n"),
        weak=("de pincode van het alarm is 8123", "De pincode van het alarm is 8123, niet delen.\n",
              "Kamer 8123 is links. Ticket 18123 is gesloten.\n"),
    ),
    "pl": dict(
        secrets=[
            ("hasło do wifi to Zebra-Lampa-77", "Zebra-Lampa-77"),
            ("hasło: Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("Hasło do routera brzmi Cedr-Polnoc-42.", "Cedr-Polnoc-42"),
            ("kod PIN to 4471", "4471"),
            ("zmieniłem hasło na Mango-Drzewo-42", "Mango-Drzewo-42"),
            ("klucz API to Ab12Cd34Ef56Gh78", "Ab12Cd34Ef56Gh78"),
        ],
        not_secrets=[
            "Hasło jest nieprawidłowe.",
            "hasło musi mieć 8 znaków",
            "menedżer haseł: Bitwarden7",
            "hasło: <twoje-hasło>",
            "klucz publiczny: ssh-ed25519AAAA1234",
            "słowa kluczowe: Python3-Async",
            "to jest hasło",
        ],
        notes=[
            ("Notatki o routerze. Hasło do wifi to Zebra-Lampa-77, zapytaj przed zmianą.\n", "Zebra-Lampa-77"),
            ("Hasło do NAS: Oliwka-Wiatr-2024\n", "Oliwka-Wiatr-2024"),
        ],
        intact=("Hasło jest wymagane przy pierwszym logowaniu. Menedżer haseł jest otwarty.\n"
                "Klucz leży w szafie, a słowo kluczowe to szybkość. Wersja 2.4.1 wyszła 2024-03-01.\n"
                "Kod jest otwarty, a pin 13 nie jest używany. Zobacz notatki.txt.\n"),
        weak=("kod PIN alarmu to 8123", "Kod PIN alarmu to 8123, nie udostępniaj.\n",
              "Pokój 8123 jest po lewej. Zgłoszenie 18123 jest zamknięte.\n"),
    ),
    "ru": dict(
        secrets=[
            ("пароль от вайфая: Zebra-Lampa-77", "Zebra-Lampa-77"),
            ("Пароль — Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("Пароль от роутера это Cedr-Sever-42.", "Cedr-Sever-42"),
            ("пин-код: 4471", "4471"),
            ("я сменил пароль на Mango-Derevo-42", "Mango-Derevo-42"),
            ("ключ API: Ab12Cd34Ef56Gh78", "Ab12Cd34Ef56Gh78"),
            ("пароль такой: Привет-Мир-2024", "Привет-Мир-2024"),
        ],
        not_secrets=[
            "Пароль неверный.",
            "пароль должен содержать 8 символов",
            "менеджер паролей: Bitwarden7",
            "пароль: <ваш-пароль>",
            "открытый ключ: ssh-ed25519AAAA1234",
            "ключевое слово: Python3-Async",
            "код ошибки: 4471",
        ],
        notes=[
            ("Заметки о роутере. Пароль от вайфая: Zebra-Lampa-77, спроси перед сменой.\n", "Zebra-Lampa-77"),
            ("Пароль от NAS: Олива-Ветер-2024\n", "Олива-Ветер-2024"),
        ],
        intact=("Пароль обязателен при первом входе. Менеджер паролей открытый.\n"
                "Ключ лежит в шкафу, а ключевое слово это скорость. Версия 2.4.1 вышла 2024-03-01.\n"
                "Код открыт, и контакт 13 не используется. См. заметки.txt.\n"),
        weak=("пин-код сигнализации: 8123", "Пин-код сигнализации: 8123, никому не говори.\n",
              "Комната 8123 слева. Заявка 18123 закрыта.\n"),
    ),
    "uk": dict(
        secrets=[
            ("пароль від вайфаю: Zebra-Lampa-77", "Zebra-Lampa-77"),
            ("Пароль — Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("Пароль до роутера це Cedr-Pivnich-42.", "Cedr-Pivnich-42"),
            ("пін-код: 4471", "4471"),
            ("я змінив пароль на Mango-Derevo-42", "Mango-Derevo-42"),
            ("ключ API: Ab12Cd34Ef56Gh78", "Ab12Cd34Ef56Gh78"),
        ],
        not_secrets=[
            "Пароль неправильний.",
            "пароль має містити 8 символів",
            "менеджер паролів: Bitwarden7",
            "пароль: <ваш-пароль>",
            "відкритий ключ: ssh-ed25519AAAA1234",
            "ключове слово: Python3-Async",
        ],
        notes=[
            ("Нотатки про роутер. Пароль від вайфаю: Zebra-Lampa-77, спитай перед зміною.\n", "Zebra-Lampa-77"),
            ("Пароль від NAS: Олива-Вітер-2024\n", "Олива-Вітер-2024"),
        ],
        intact=("Пароль обов'язковий під час першого входу. Менеджер паролів відкритий.\n"
                "Ключ лежить у шафі, а ключове слово це швидкість. Версія 2.4.1 вийшла 2024-03-01.\n"
                "Код відкритий, і контакт 13 не використовується. Див. нотатки.txt.\n"),
        weak=("пін-код сигналізації: 8123", "Пін-код сигналізації: 8123, нікому не кажи.\n",
              "Кімната 8123 ліворуч. Заявка 18123 закрита.\n"),
    ),
    "zh-CN": dict(
        secrets=[
            ("WiFi密码是Zebra-Lamp-77", "Zebra-Lamp-77"),
            ("密码：Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("路由器的密码是 Cedar-North-42，别告诉别人。", "Cedar-North-42"),
            ("PIN码是4471", "4471"),
            ("我把密码改成了Mango-Tree-42", "Mango-Tree-42"),
            ("API密钥：Ab12Cd34Ef56Gh78", "Ab12Cd34Ef56Gh78"),
            ("密码为Olive-Wind-2024。", "Olive-Wind-2024"),
            ("密码是「括号里的Pass2024」", "括号里的Pass2024"),
        ],
        not_secrets=[
            "密码错误",
            "密码不正确，请重试",
            "密码必须包含8个字符",
            "密码管理器：Bitwarden7",
            "请输入密码：",
            "密码学：RSA2048-OAEP",
            "密码：<你的密码>",
            "公钥：ssh-ed25519AAAA1234",
            "邮政编码是100000",
        ],
        notes=[
            ("路由器笔记。WiFi密码是Zebra-Lamp-77，修改前请先询问。\n", "Zebra-Lamp-77"),
            ("NAS 的密码：Olive-Wind-2024\n", "Olive-Wind-2024"),
        ],
        intact=("首次登录时必须输入密码。密码管理器是开源的。\n"
                "钥匙在柜子里，关键词是速度。版本 2.4.1 于 2024-03-01 发布。\n"
                "代码是开放的，密码学是一门学科。请参阅 notes.txt。\n"),
        weak=("报警器的PIN码是8123", "报警器的PIN码是8123，不要告诉别人。\n",
              "8123 号房间在左边。工单 18123 已关闭。\n"),
    ),
    "ja": dict(
        secrets=[
            ("Wi-Fiのパスワードは Zebra-Lamp-77 です", "Zebra-Lamp-77"),
            ("パスワード：Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("ルーターのパスワードはCedar-North-42です。", "Cedar-North-42"),
            ("暗証番号は4471です", "4471"),
            ("パスワードをMango-Tree-42に変更しました", "Mango-Tree-42"),
            ("APIキー：Ab12Cd34Ef56Gh78", "Ab12Cd34Ef56Gh78"),
        ],
        not_secrets=[
            "パスワードが間違っています",
            "パスワードは8文字以上にしてください",
            "パスワードは必須です",
            "パスワードマネージャー：Bitwarden7",
            "パスワード：<あなたのパスワード>",
            "公開鍵：ssh-ed25519AAAA1234",
            "パスワードを忘れた場合は support-2024 へ",
        ],
        notes=[
            ("ルーターのメモ。Wi-Fiのパスワードは Zebra-Lamp-77 です。変更前に確認してください。\n", "Zebra-Lamp-77"),
            ("NASのパスワード：Olive-Wind-2024\n", "Olive-Wind-2024"),
        ],
        intact=("初回ログインにはパスワードが必須です。パスワードマネージャーはオープンソースです。\n"
                "鍵は棚にあり、キーワードは速度です。バージョン 2.4.1 は 2024-03-01 に公開されました。\n"
                "コードは公開されています。notes.txt を参照してください。\n"),
        weak=("警報の暗証番号は8123です", "警報の暗証番号は8123です。共有しないでください。\n",
              "8123 号室は左です。チケット 18123 は閉じています。\n"),
    ),
    "ko": dict(
        secrets=[
            ("와이파이 비밀번호는 Zebra-Lamp-77 입니다", "Zebra-Lamp-77"),
            ("비밀번호: Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("공유기 비밀번호는 Cedar-North-42입니다.", "Cedar-North-42"),
            ("PIN 번호는 4471입니다", "4471"),
            ("비밀번호를 Mango-Tree-42로 바꿨어요", "Mango-Tree-42"),
            ("API 키: Ab12Cd34Ef56Gh78", "Ab12Cd34Ef56Gh78"),
        ],
        not_secrets=[
            "비밀번호가 틀렸습니다",
            "비밀번호는 8자 이상이어야 합니다",
            "비밀번호는 필수입니다",
            "비밀번호 관리자: Bitwarden7",
            "비밀번호: <비밀번호>",
            "암호화 방식은 AES256-GCM입니다",
            "공개 키: ssh-ed25519AAAA1234",
        ],
        notes=[
            ("공유기 메모. 와이파이 비밀번호는 Zebra-Lamp-77 입니다. 바꾸기 전에 물어보세요.\n", "Zebra-Lamp-77"),
            ("NAS 비밀번호: Olive-Wind-2024\n", "Olive-Wind-2024"),
        ],
        intact=("처음 로그인할 때 비밀번호는 필수입니다. 비밀번호 관리자는 오픈 소스입니다.\n"
                "열쇠는 선반에 있고 핵심은 속도입니다. 버전 2.4.1은 2024-03-01에 나왔습니다.\n"
                "암호화 방식은 표준입니다. notes.txt를 참고하세요.\n"),
        weak=("경보기 PIN 번호는 8123입니다", "경보기 PIN 번호는 8123입니다. 공유하지 마세요.\n",
              "8123호는 왼쪽입니다. 티켓 18123은 닫혔습니다.\n"),
    ),
    "th": dict(
        secrets=[
            ("รหัสผ่าน wifi คือ Zebra-Lamp-77", "Zebra-Lamp-77"),
            ("รหัสผ่าน: Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("รหัสผ่านของเราเตอร์คือ Cedar-North-42", "Cedar-North-42"),
            ("รหัส PIN คือ 4471", "4471"),
            ("รหัสผ่านคือMango-Tree-42นะครับ", "Mango-Tree-42"),
            ("โทเค็น: Ab12Cd34Ef56Gh78", "Ab12Cd34Ef56Gh78"),
        ],
        not_secrets=[
            "รหัสผ่านไม่ถูกต้อง",
            "รหัสผ่านต้องมีอย่างน้อย 8 ตัวอักษร",
            "รหัสผ่านคือสิ่งสำคัญ",
            "ตัวจัดการรหัสผ่าน: Bitwarden7",
            "รหัสผ่าน: <รหัสผ่านของคุณ>",
            "รหัสไปรษณีย์คือ 10110",
        ],
        notes=[
            ("บันทึกเราเตอร์ รหัสผ่าน wifi คือ Zebra-Lamp-77 ถามก่อนเปลี่ยน\n", "Zebra-Lamp-77"),
            ("รหัสผ่านของ NAS: Olive-Wind-2024\n", "Olive-Wind-2024"),
        ],
        intact=("ต้องใช้รหัสผ่านเมื่อเข้าสู่ระบบครั้งแรก ตัวจัดการรหัสผ่านเป็นโอเพนซอร์ส\n"
                "กุญแจอยู่ในตู้ และคำสำคัญคือความเร็ว เวอร์ชัน 2.4.1 ออกเมื่อ 2024-03-01\n"
                "โค้ดเปิดเผย รหัสไปรษณีย์คือ 10110 ดู notes.txt\n"),
        weak=("รหัส PIN ของสัญญาณเตือนคือ 8123", "รหัส PIN ของสัญญาณเตือนคือ 8123 ห้ามบอกใคร\n",
              "ห้อง 8123 อยู่ทางซ้าย ตั๋ว 18123 ปิดแล้ว\n"),
    ),
    "hi": dict(
        secrets=[
            ("वाईफाई का पासवर्ड Zebra-Lamp-77 है", "Zebra-Lamp-77"),
            ("पासवर्ड: Tr0ub4dor&3x", "Tr0ub4dor&3x"),
            ("राउटर का पासवर्ड है Cedar-North-42।", "Cedar-North-42"),
            ("मेरा पिन 4471 है", "4471"),
            ("पासवर्ड यह है: Mango-Tree-42", "Mango-Tree-42"),
            ("एपीआई टोकन: Ab12Cd34Ef56Gh78", "Ab12Cd34Ef56Gh78"),
        ],
        not_secrets=[
            "पासवर्ड गलत है",
            "पासवर्ड कम से कम 8 अक्षरों का होना चाहिए",
            "पासवर्ड प्रबंधक: Bitwarden7",
            "पासवर्ड: <आपका-पासवर्ड>",
            "पासवर्ड सही है",
            "यह पासवर्ड बहुत ज़रूरी है",
        ],
        notes=[
            ("राउटर के नोट। वाईफाई का पासवर्ड Zebra-Lamp-77 है, बदलने से पहले पूछें।\n", "Zebra-Lamp-77"),
            ("NAS का पासवर्ड: Olive-Wind-2024\n", "Olive-Wind-2024"),
        ],
        intact=("पहली बार लॉगिन के समय पासवर्ड ज़रूरी है। पासवर्ड प्रबंधक मुक्त स्रोत है।\n"
                "चाबी अलमारी में है और मुख्य बात गति है। संस्करण 2.4.1 2024-03-01 को आया।\n"
                "कोड खुला है। notes.txt देखें।\n"),
        weak=("अलार्म का पिन 8123 है", "अलार्म का पिन 8123 है, किसी को न बताएँ।\n",
              "कमरा 8123 बाईं ओर है। टिकट 18123 बंद है।\n"),
    ),
}
