# Data Management module (Anirudh) - Phase 2

## Files
- src/data/Normalizer.h/.cpp     clean + classify every URL / IP
- src/data/Storage.h             abstract storage interface
- src/data/FileStorage.h/.cpp    text-file implementation (SQLite in Phase 3)
- src/data/FeedImporter.h/.cpp   import plain-text lists (URLhaus text, OpenPhish, sample)
- include/tracker.h              shared types (use Mohit's final version)
- tests/                         test_normalizer.cpp (19 tests), test_storage.cpp (26 tests)
- demo/data_demo.cpp             runs the whole module on its own
- data/                          FAKE sample data only

## Build and run (from this folder)
    g++ -std=c++17 -Wall -Iinclude tests/test_normalizer.cpp src/data/Normalizer.cpp -o test_normalizer
    g++ -std=c++17 -Wall -Iinclude tests/test_storage.cpp src/data/FileStorage.cpp src/data/FeedImporter.cpp src/data/Normalizer.cpp -o test_storage
    g++ -std=c++17 -Wall -Iinclude demo/data_demo.cpp src/data/FileStorage.cpp src/data/FeedImporter.cpp src/data/Normalizer.cpp -o data_demo

    ./test_normalizer      (Windows: test_normalizer.exe)
    ./test_storage
    ./data_demo            (run twice: second run imports 0 new = data was saved)

Works on older compilers too (no <filesystem> needed).

## Decisions
- "www." is stripped; default ports 80/443 removed; path case kept.
- Leading zeros in IPv4 (01.2.3.4) are rejected.
- Feed entries stay exact "URL" entries; only sample/admin hosts become "DOMAIN" (subdomains blocked).
- History never stores query strings (?...), for privacy.
