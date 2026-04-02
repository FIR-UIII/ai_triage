import os
from sentence_transformers import SentenceTransformer
from chromadb import PersistentClient

# Define the directory containing the text file and the persistent directory
current_dir = os.path.dirname(os.path.abspath(__file__))
persistent_directory = os.path.join(current_dir, "chroma_db_metadata")

# Загружаем локальную модель (например, all-MiniLM-L6-v2, размерность 384)
model = SentenceTransformer('all-MiniLM-L6-v2')

# Инициализация клиента ChromaDB
client = PersistentClient(path=persistent_directory)

# Ручной ввод данных с метаданными
collection = client.create_collection(
    name="example_collection"
)

# если нужно добавить в коллекцию документ
# collection = client.get_or_create_collection(name="example_collection")

# # в несколько за раз
# collection.add(
#     ids=["id1", "id2", "id3"],
#     documents=["lorem ipsum...", "doc2", "doc3"],
#     metadatas=[{"chapter": 3, "verse": 16}, {"chapter": 3, "verse": 5}, {"chapter": 29, "verse": 11}],
# )

# ввод по одному
collection.add(
    ids=["1"],
    documents=["Файт содержит в названии _test и расположен в каталоге documents для описания документации и примеров использования, такие файлы не используются в продуктивной сборке"],
    metadatas=[{
        "id": "2726557", 
        "source": "semgrep", 
        "product_id": 298,
        "date": "2025-12-05",
        "file_path": "/builds/source/gren-hrtech/iam-team/iam/source/atomid-bundle/documents/api/templates/operation_test.hbs",
        "component_name": "",
        "component_version": "",
        "description": "Detected a template variable used in an anchor tag with the 'href' attribute. This allows a malicious actor to input the 'javascript:' URI and is subject to cross- site scripting (XSS) attacks. If using Flask, use 'url_for()' to safely generate a URL. If using Django, use the 'url' filter to safely generate a URL. If using Mustache, use a URL encoding library, or prepend a slash '/' to the variable for relative links (`href=\"/{{link}}\"`). You may also consider setting the Content Security Policy (CSP) header.\n**Snippet:**\n```<p>{{#if externalDocs.url}}{{externalDocs.description}}. <a href=\"{{externalDocs.url}}\">See external documents for more inforamtion",
        "cve": "",
        "rule": "app.rules.generic.html-templates.security.var-in-href",
        "hash": "foohash"}
    ],
)

collection.add(
    ids=["2"],
    documents=["False-positive. Используемая версия libarchive 3.8.1-1.el7 содержит исправление уязвимости согласно документации вендора"],
    metadatas=[{
        "id": "2728961", 
        "source": "dependency_track", 
        "product_id": 298,
        "date": "2025-10-02",
        "file_path": "pkg:rpm/redos/libarchive@3.8.1-1.el7?arch=x86_64&distro=redos-7.3&epoch=0&upstream=libarchive-3.8.1-1.el7.src.rpm",
        "component_name": "libarchive",
        "component_version": "3.8.1-1.el7",
        "description": "TODO",
        "cve": "CVE-2015-8930",
        "rule": "",
        "hash": ""}
    ],
)

collection.add(
    ids=["3"],
    documents=["Используется версия 1.1.1zd-1.el7 содержащее исправление (патч) от вендора РедОС, подробнее см. https://redos.red-soft.ru/search/?iblock_id=24&q=openssl Сканер не интерпритирует корректно буквенное обозначение минорной версии `zd` ориентируясь на цифровое наименование. Например для CVE-2021-3711 уязвимая версия до 1.1.1l (не включая)"],
    metadatas=[{
        "id": "2728961",
        "product_type": "iam", # TODO: добавил поле
        "product_name": "atomid", # TODO: добавил поле
        "source": "dependency_track", 
        "product_id": 298,
        "date": "2026-03-12",
        "file_path": "pkg:rpm/redos/libarchive@3.8.1-1.el7?arch=x86_64&distro=redos-7.3&epoch=0&upstream=libarchive-3.8.1-1.el7.src.rpm",
        "component_name": "openssl",
        "component_version": "1:1.1.1zd-1.el7",
        "cve": "CVE-2015-8930",
        "description": "You are using a component with a known vulnerability. Version 1:1.1.1zd-1.el7 of the openssl component is affected by the vulnerability with an id of CVE-2019-1543 as identified by NVD.\nThe purl of the affected component is: pkg:rpm/redos/openssl@1.1.1zd-1.el7?arch=x86_64&distro=redos-7.3&epoch=1&upstream=openssl-1.1.1zd-1.el7.src.rpm.\nVulnerability Description: ChaCha20-Poly1305 is an AEAD cipher, and requires a unique nonce input for every encryption operation. RFC 7539 specifies that the nonce value (IV) should be 96 bits (12 bytes). OpenSSL allows a variable nonce length and front pads the nonce with 0 bytes if it is less than 12 bytes. However it also incorrectly allows a nonce to be set of up to 16 bytes. In this case only the last 12 bytes are significant and any additional leading bytes are ignored. It is a requirement of using this cipher that nonce values are unique. Messages encrypted using a reused nonce value are susceptible to serious confidentiality and integrity attacks. If an application changes the default nonce length to be longer than 12 bytes and then makes a change to the leading bytes of the nonce expecting the new value to be a new unique nonce then such an application could inadvertently encrypt messages with a reused nonce. Additionally the ignored bytes in a long nonce are not covered by the integrity guarantee of this cipher. Any application that relies on the integrity of these ignored leading bytes of a long nonce may be further affected. Any OpenSSL internal use of this cipher, including in SSL/TLS, is safe because no such use sets such a long nonce value. However user applications that use this cipher directly and set a non-default nonce length to be longer than 12 bytes may be vulnerable. OpenSSL versions 1.1.1 and 1.1.0 are affected by this issue. Due to the limited scope of affected deployments this has been assessed as low severity and therefore we are not creating new releases at this time. Fixed in OpenSSL 1.1.1c (Affected 1.1.1-1.1.1b). Fixed in OpenSSL 1.1.0k (Affected 1.1.0-1.1.0j).",
        "rule": "",
        "hash": ""}
    ],
)