/*
    srcFacts.cpp

    Produces a report with various measures of C++, C, Java,
    and C# source-code.

    Input is an XML file in the srcML format.

    Output a markdown table with the measures.

    Output performance statistics to stdlog.

    Code includes an XML parser with some limitations:
    * No checking for well-formedness
    * No DTD declarations
*/

#include <iostream>
#include <locale>
#include <iterator>
#include <string>
#include <algorithm>
#include <cstring>
#include <sys/types.h>
#include <errno.h>
#include <ctype.h>
#include <string_view>
#include <optional>
#include <iomanip>
#include <cmath>
#include <algorithm>
#include <chrono>
#include <memory>
#include <string.h>
#include <stdlib.h>

#if !defined(_MSC_VER)
#include <sys/uio.h>
#include <unistd.h>
#define READ read
#else
#include <BaseTsd.h>
#include <io.h>
typedef SSIZE_T ssize_t;
#define READ _read
#endif

// provides literal string operator""sv
using namespace std::literals::string_view_literals;

const int BUFFER_SIZE = 16 * 16 * 4096;

/*
    Refill the buffer preserving the unused data.
    Current content [cursor, cursorEnd) is shifted left and new data
    appended to the rest of the buffer.

    @param[in,out] cursor Iterator to current position in buffer
    @param[in, out] cursorEnd Iterator to end of buffer for this read
    @param[in, out] buffer Container for characters
    @return Number of bytes read
    @retval 0 EOF
    @retval -1 Read error
*/
int refillBuffer(std::string::const_iterator& cursor, std::string::const_iterator& cursorEnd, std::string& buffer) {

    // number of unprocessed characters [cursor, cursorEnd)
    size_t unprocessed = std::distance(cursor, cursorEnd);

    // move unprocessed characters, [cursor, cursorEnd), to start of the buffer
    std::copy(cursor, cursorEnd, buffer.begin());

    // reset cursors
    cursor = buffer.begin();
    cursorEnd = cursor + unprocessed;

    // read in whole blocks
    ssize_t readBytes = 0;
    while (((readBytes = READ(0, static_cast<void*>(buffer.data() + unprocessed),
        std::distance(cursorEnd, buffer.cend()))) == -1) && (errno == EINTR)) {
    }
    if (readBytes == -1)
        // error in read
        return -1;
    if (readBytes == 0) {
        // EOF
        cursor = buffer.cend();
        cursorEnd = buffer.cend();
        return 0;
    }

    // adjust the end of the cursor to the new bytes
    cursorEnd += readBytes;

    return readBytes;
}

#ifdef DOTRACE
#define TRACE(m,n) std::clog << m << ": |" << n << "|\n";
#else
#define TRACE(m,n)
#endif

int main() {
    const auto start = std::chrono::steady_clock::now();
    std::string url;
    int textsize = 0;
    int loc = 0;
    int exprCount = 0;
    int functionCount = 0;
    int classCount = 0;
    int unitCount = 0;
    int declCount = 0;
    int commentCount = 0;
    int depth = 0;
    long totalBytes = 0;
    bool inTag = false;
    bool isArchive = false;
    std::string buffer(BUFFER_SIZE, ' ');
    std::string::const_iterator cursor = buffer.cend();
    std::string::const_iterator cursorEnd = buffer.cend();
    while (true) {
        if (std::distance(cursor, cursorEnd) < 5) {
            // refill buffer and adjust iterator
            int bytesRead = refillBuffer(cursor, cursorEnd, buffer);
            if (bytesRead < 0) {
                std::cerr << "parser error : File input error\n";
                return 1;
            }
            totalBytes += bytesRead;
            if (cursor == cursorEnd)
                break;
        } else if (inTag && (strncmp(std::addressof(*cursor), "xmlns", 5) == 0) && (cursor[5] == ':' || cursor[5] == '=')) {
            // parse XML namespace
            std::advance(cursor, 5);
            const std::string::const_iterator tagEnd = std::find(cursor, cursorEnd, '>');
            const std::string::const_iterator nameEnd = std::find(cursor, std::next(tagEnd), '=');
            if (nameEnd == std::next(tagEnd)) {
                std::cerr << "parser error : incomplete namespace\n";
                return 1;
            }
            int prefixSize = 0;
            if (*cursor == ':') {
                std::advance(cursor, 1);
                prefixSize = std::distance(cursor, nameEnd);
            }
            const std::string_view prefix(std::addressof(*cursor), prefixSize);
            TRACE("Namespace prefix", prefix);
            cursor = std::next(nameEnd);
            cursor = std::find_if_not(cursor, std::next(tagEnd), isspace);
            if (cursor == std::next(tagEnd)) {
                std::cerr << "parser error : incomplete namespace\n";
                return 1;
            }
            const char delimiter = *cursor;
            if (delimiter != '"' && delimiter != '\'') {
                std::cerr << "parser error : incomplete namespace\n";
                return 1;
            }
            std::advance(cursor, 1);
            const std::string::const_iterator valueEnd = std::find(cursor, std::next(tagEnd), delimiter);
            if (valueEnd == std::next(tagEnd)) {
                std::cerr << "parser error : incomplete namespace\n";
                return 1;
            }
            const std::string_view uri(std::addressof(*cursor), std::distance(cursor, valueEnd));
            TRACE("Namespace uri", uri);
            cursor = std::next(valueEnd);
            cursor = std::find_if_not(cursor, std::next(tagEnd), isspace);
            if (inTag && *cursor == '>') {
                std::advance(cursor, 1);
                inTag = false;
                ++depth;
            }
            if (inTag && *cursor == '/' && cursor[1] == '>') {
                std::advance(cursor, 2);
                inTag = false;
            }
        } else if (inTag) {
            // parse attribute
            const std::string::const_iterator tagEnd = std::find(cursor, cursorEnd, '>');
            const std::string::const_iterator nameEnd = std::find(cursor, std::next(tagEnd), '=');
            if (nameEnd == std::next(tagEnd))
                return 1;
            const std::string_view qName(std::addressof(*cursor), std::distance(cursor, nameEnd));
            TRACE("ATTR qName", qName);
            size_t colonPosition = qName.find(':');
            if (colonPosition == 0) {
                std::cerr << "parser error : Invalid attribute name\n";
                return 1;
            }
            if (colonPosition == std::string::npos)
                colonPosition = 0;
            const std::string_view prefix(std::addressof(*qName.cbegin()), colonPosition);
            TRACE("ATTR prefix", prefix);
            if (colonPosition != 0)
                colonPosition += 1;
            const std::string_view localName(std::addressof(*qName.cbegin()) + colonPosition, qName.size() - colonPosition);
            TRACE("ATTR localName", localName);
            cursor = std::next(nameEnd);
            cursor = std::find_if_not(cursor, std::next(tagEnd), isspace);
            if (cursor == cursorEnd) {
                std::cerr << "parser error : attribute " << qName << " incomplete attribute\n";
                return 1;
            }
            const char delimiter = *cursor;
            if (delimiter != '"' && delimiter != '\'') {
                std::cerr << "parser error : attribute " << qName << " missing delimiter\n";
                return 1;
            }
            std::advance(cursor, 1);
            std::string::const_iterator valueEnd = std::find(cursor, std::next(tagEnd), delimiter);
            if (valueEnd == std::next(tagEnd)) {
                std::cerr << "parser error : attribute " << qName << " missing delimiter\n";
                return 1;
            }
            const std::string_view value(std::addressof(*cursor), std::distance(cursor, valueEnd));
            TRACE("ATTR value", value);
            if (localName == "url"sv)
                url = value;
            cursor = std::next(valueEnd);
            cursor = std::find_if_not(cursor, std::next(tagEnd), isspace);
            if (inTag && *cursor == '>') {
                std::advance(cursor, 1);
                inTag = false;
                ++depth;
            }
            if (inTag && *cursor == '/' && cursor[1] == '>') {
                std::advance(cursor, 2);
                inTag = false;
            }
        } else if (cursor[1] == '?' && *cursor == '<' && (strncmp(std::addressof(*cursor), "<?xml", 5) == 0)) {
            // parse XML declaration
            constexpr std::string_view startXMLDecl = "<?xml";
            constexpr std::string_view endXMLDecl = "?>";
            std::string::const_iterator tagEnd = std::find(cursor, cursorEnd, '>');
            if (tagEnd == cursorEnd) {
                int bytesRead = refillBuffer(cursor, cursorEnd, buffer);
                if (bytesRead < 0) {
                    std::cerr << "parser error : File input error\n";
                    return 1;
                }
                totalBytes += bytesRead;
                if ((tagEnd = std::find(cursor, cursorEnd, '>')) == cursorEnd) {
                    std::cerr << "parser error: Incomplete XML declaration\n";
                    return 1;
                }
            }
            std::advance(cursor, startXMLDecl.size());
            cursor = std::find_if_not(cursor, tagEnd, isspace);
            // parse required version
            if (cursor == tagEnd) {
                std::cerr << "parser error: Missing space after before version in XML declaration\n";
                return 1;
            }
            std::string::const_iterator nameEnd = std::find(cursor, tagEnd, '=');
            const std::string_view attr(std::addressof(*cursor), std::distance(cursor, nameEnd));
            cursor = std::next(nameEnd);
            const char delimiter = *cursor;
            if (delimiter != '"' && delimiter != '\'') {
                std::cerr << "parser error: Invalid start delimiter for version in XML declaration\n";
                return 1;
            }
            std::advance(cursor, 1);
            std::string::const_iterator valueEnd = std::find(cursor, tagEnd, delimiter);
            if (valueEnd == tagEnd) {
                std::cerr << "parser error: Invalid end delimiter for version in XML declaration\n";
                return 1;
            }
            if (attr != "version"sv) {
                std::cerr << "parser error: Missing required first attribute version in XML declaration\n";
                return 1;
            }
            const std::string_view version(std::addressof(*cursor), std::distance(cursor, valueEnd));
            cursor = std::next(valueEnd);
            cursor = std::find_if_not(cursor, tagEnd, isspace);
            // parse optional encoding and standalone attributes
            std::optional<std::string_view> encoding;
            std::optional<std::string_view> standalone;
            if (cursor != (tagEnd - endXMLDecl.size())) {
                nameEnd = std::find(cursor, tagEnd, '=');
                if (nameEnd == tagEnd) {
                    std::cerr << "parser error: Incomplete attribute in XML declaration\n";
                    return 1;
                }
                const std::string_view attr2(std::addressof(*cursor), std::distance(cursor, nameEnd));
                cursor = std::next(nameEnd);
                char delimiter2 = *cursor;
                if (delimiter2 != '"' && delimiter2 != '\'') {
                    std::cerr << "parser error: Invalid end delimiter for attribute " << attr2 << " in XML declaration\n";
                    return 1;
                }
                std::advance(cursor, 1);
                valueEnd = std::find(cursor, tagEnd, delimiter2);
                if (valueEnd == tagEnd) {
                    std::cerr << "parser error: Incomplete attribute " << attr2 << " in XML declaration\n";
                    return 1;
                }
                if (attr2 == "encoding"sv) {
                    encoding = std::string_view(std::addressof(*cursor), std::distance(cursor, valueEnd));
                } else if (attr2 == "standalone"sv) {
                    standalone = std::string_view(std::addressof(*cursor), std::distance(cursor, valueEnd));
                } else {
                    std::cerr << "parser error: Invalid attribute " << attr2 << " in XML declaration\n";
                    return 1;
                }
                cursor = std::next(valueEnd);
                cursor = std::find_if_not(cursor, tagEnd, isspace);
            }
            if (cursor != (tagEnd - endXMLDecl.size() + 1)) {
                nameEnd = std::find(cursor, tagEnd, '=');
                if (nameEnd == tagEnd) {
                    std::cerr << "parser error: Incomplete attribute in XML declaration\n";
                    return 1;
                }
                const std::string_view attr2(std::addressof(*cursor), std::distance(cursor, nameEnd));
                cursor = std::next(nameEnd);
                const char delimiter2 = *cursor;
                if (delimiter2 != '"' && delimiter2 != '\'') {
                    std::cerr << "parser error: Invalid end delimiter for attribute " << attr2 << " in XML declaration\n";
                    return 1;
                }
                std::advance(cursor, 1);
                valueEnd = std::find(cursor, tagEnd, delimiter2);
                if (valueEnd == tagEnd) {
                    std::cerr << "parser error: Incomplete attribute " << attr2 << " in XML declaration\n";
                    return 1;
                }
                if (!standalone && attr2 == "standalone"sv) {
                    standalone = std::string_view(std::addressof(*cursor), std::distance(cursor, valueEnd));
                } else {
                    std::cerr << "parser error: Invalid attribute " << attr2 << " in XML declaration\n";
                    return 1;
                }
                cursor = std::next(valueEnd);
                cursor = std::find_if_not(cursor, tagEnd, isspace);
            }
            std::advance(cursor, endXMLDecl.size());
            cursor = std::find_if_not(cursor, cursorEnd, isspace);
        } else if (cursor[1] == '!' && *cursor == '<' && cursor[2] == '[' && (strncmp(std::addressof(cursor[3]), "CDATA[", 6) == 0)) {
            // parse CDATA
            constexpr std::string_view endCDATA = "]]>"sv;
            std::advance(cursor, 9);
            std::string::const_iterator tagEnd = std::search(cursor, cursorEnd, endCDATA.begin(), endCDATA.end());
            if (tagEnd == cursorEnd) {
                int bytesRead = refillBuffer(cursor, cursorEnd, buffer);
                if (bytesRead < 0) {
                    std::cerr << "parser error : File input error\n";
                    return 1;
                }
                totalBytes += bytesRead;
                if ((tagEnd = std::search(cursor, cursorEnd, endCDATA.begin(), endCDATA.end())) == cursorEnd)
                    return 1;
            }
            const std::string_view characters(std::addressof(*cursor), std::distance(cursor, tagEnd));
            TRACE("CDATA", characters);
            textsize += static_cast<int>(characters.size());
            loc += static_cast<int>(std::count(characters.begin(), characters.end(), '\n'));
            cursor = std::next(tagEnd, endCDATA.size());
        } else if (cursor[1] == '!' && *cursor == '<' && cursor[2] == '-' && cursor[3] == '-') {
            // parse XML comment
            constexpr std::string_view endComment = "-->";
            std::string::const_iterator tagEnd = std::search(cursor, cursorEnd, endComment.begin(), endComment.end());
            if (tagEnd == cursorEnd) {
                int bytesRead = refillBuffer(cursor, cursorEnd, buffer);
                if (bytesRead < 0) {
                    std::cerr << "parser error : File input error\n";
                    return 1;
                }
                totalBytes += bytesRead;
                if ((tagEnd = std::search(cursor, cursorEnd, endComment.begin(), endComment.end())) == cursorEnd) {
                    std::cerr << "parser error : Unterminated XML comment\n";
                    return 1;
                }
            }
            const std::string_view comment(std::addressof(*cursor), std::distance(cursor, tagEnd));
            TRACE("Comment", comment);
            cursor = std::next(tagEnd, endComment.size());
            cursor = std::find_if_not(cursor, cursorEnd, isspace);
        } else if (cursor[1] == '/' && *cursor == '<') {
            // parse end tag
            std::string::const_iterator tagEnd = std::find(cursor, cursorEnd, '>');
            if (tagEnd == cursorEnd) {
                int bytesRead = refillBuffer(cursor, cursorEnd, buffer);
                if (bytesRead < 0) {
                    std::cerr << "parser error : File input error\n";
                    return 1;
                }
                totalBytes += bytesRead;
                if ((tagEnd = std::find(cursor, cursorEnd, '>')) == cursorEnd) {
                    std::cerr << "parser error: Incomplete element end tag\n";
                    return 1;
                }
            }
            std::advance(cursor, 2);
            const std::string::const_iterator nameEnd = std::find_if_not(cursor, std::next(tagEnd), [] (char c) { return isalnum(c) || c == ':' || c == '_' || c == '-' || c == '.'; });
            if (nameEnd == std::next(tagEnd)) {
                std::cerr << "parser error: Incomplete element end tag name\n";
                return 1;
            }
            const std::string_view qName(std::addressof(*cursor), std::distance(cursor, nameEnd));
            TRACE("End Tag qName", qName);
            size_t colonPosition = qName.find(':');
            if (colonPosition == 0) {
                std::cerr << "parser error : Invalid end tag name\n";
                return 1;
            }
            if (colonPosition == std::string::npos)
                colonPosition = 0;
            const std::string_view prefix(std::addressof(*qName.cbegin()), colonPosition);
            TRACE("End Tag prefix", prefix);
            if (colonPosition != 0)
                colonPosition += 1;
            const std::string_view localName(std::addressof(*qName.cbegin()) + colonPosition, qName.size() - colonPosition);
            TRACE("End Tag localName", localName);
            cursor = std::next(tagEnd);
            --depth;
        } else if (*cursor == '<') {
            // parse start tag
            std::string::const_iterator tagEnd = std::find(cursor, cursorEnd, '>');
            if (tagEnd == cursorEnd) {
                int bytesRead = refillBuffer(cursor, cursorEnd, buffer);
                if (bytesRead < 0) {
                    std::cerr << "parser error : File input error\n";
                    return 1;
                }
                totalBytes += bytesRead;
                if ((tagEnd = std::find(cursor, cursorEnd, '>')) == cursorEnd) {
                    std::cerr << "parser error: Incomplete element start tag\n";
                    return 1;
                }
            }
            std::advance(cursor, 1);
            const std::string::const_iterator nameEnd = std::find_if_not(cursor, std::next(tagEnd), [] (char c) { return isalnum(c) || c == ':' || c == '_' || c == '-' || c == '.'; });
            if (nameEnd == std::next(tagEnd)) {
                std::cerr << "parser error : Unterminated start tag '" << std::string_view(std::addressof(*cursor), std::distance(cursor, nameEnd)) << "'\n";
                return 1;
            }
            const std::string_view qName(std::addressof(*cursor), std::distance(cursor, nameEnd));
            if (qName.empty()) {
                std::cerr << "parser error: StartTag: invalid element name\n";
                return 1;
            }
            TRACE("Str Tag qName", qName);
            size_t colonPosition = qName.find(':');
            if (colonPosition == 0) {
                std::cerr << "parser error : Invalid start tag name\n";
                return 1;
            }
            if (colonPosition == std::string::npos)
                colonPosition = 0;
            const std::string_view prefix(std::addressof(*qName.cbegin()), colonPosition);
            TRACE("Str Tag prefix", prefix);
            if (colonPosition != 0)
                colonPosition += 1;
            const std::string_view localName(std::addressof(*qName.cbegin()) + colonPosition, qName.size() - colonPosition);
            TRACE("Str Tag localName", localName);
            if (localName == "expr"sv) {
                ++exprCount;
            } else if (localName == "decl"sv) {
                ++declCount;
            } else if (localName == "comment"sv) {
                ++commentCount;
            } else if (localName == "function"sv) {
                ++functionCount;
            } else if (localName == "unit"sv) {
                ++unitCount;
                if (depth == 1)
                    isArchive = true;
            } else if (localName == "class"sv) {
                ++classCount;
            }
            cursor = nameEnd;
            cursor = std::find_if_not(cursor, std::next(tagEnd), isspace);
            inTag = true;
            if (inTag && *cursor == '>') {
                std::advance(cursor, 1);
                inTag = false;
                ++depth;
            }
            if (inTag && *cursor == '/' && cursor[1] == '>') {
                std::advance(cursor, 2);
                inTag = false;
            }
        } else if (depth == 0) {
            // parse characters before or after XML
            cursor = std::find_if_not(cursor, cursorEnd, isspace);
        } else if (*cursor == '&') {
            // parse character entity references
            std::string_view characters;
            if (cursor[1] == 'l' && cursor[2] == 't' && cursor[3] == ';') {
                characters = "<";
                std::advance(cursor, 4);
            } else if (cursor[1] == 'g' && cursor[2] == 't' && cursor[3] == ';') {
                characters = ">";
                std::advance(cursor, 4);
            } else if (cursor[1] == 'a' && cursor[2] == 'm' && cursor[3] == 'p' && cursor[4] == ';') {
                characters = "&";
                std::advance(cursor, 5);
            } else {
                characters = "&";
                std::advance(cursor, 1);
            }
            TRACE("ENTREF", characters);
            ++textsize;

        } else {
            // parse character non-entity references
            const std::string::const_iterator tagEnd = std::find_if(cursor, cursorEnd, [] (char c) { return c == '<' || c == '&'; });
            const std::string_view characters(std::addressof(*cursor), std::distance(cursor, tagEnd));
            TRACE("Characters", characters);
            loc += static_cast<int>(std::count(characters.cbegin(), characters.cend(), '\n'));
            textsize += static_cast<int>(characters.size());
            cursor = tagEnd;
        }
    }
    const auto finish = std::chrono::steady_clock::now();
    const auto elapsed_seconds = std::chrono::duration_cast<std::chrono::duration<double> >(finish - start).count();
    const double mlocPerSec = loc / elapsed_seconds / 1000000;
    int files = unitCount;
    if (isArchive)
        --files;
    std::cout.imbue(std::locale{""});
    int valueWidth = std::max(5, static_cast<int>(log10(totalBytes) * 1.3 + 1));
    std::cout << "# srcFacts: " << url << '\n';
    std::cout << "| Measure      | " << std::setw(valueWidth + 3) << "Value |\n";
    std::cout << "|:-------------|-" << std::setw(valueWidth + 3) << std::setfill('-') << ":|\n" << std::setfill(' ');
    std::cout << "| srcML bytes  | " << std::setw(valueWidth) << totalBytes          << " |\n";
    std::cout << "| Characters   | " << std::setw(valueWidth) << textsize       << " |\n";
    std::cout << "| Files        | " << std::setw(valueWidth) << files          << " |\n";
    std::cout << "| LOC          | " << std::setw(valueWidth) << loc            << " |\n";
    std::cout << "| Classes      | " << std::setw(valueWidth) << classCount    << " |\n";
    std::cout << "| Functions    | " << std::setw(valueWidth) << functionCount << " |\n";
    std::cout << "| Declarations | " << std::setw(valueWidth) << declCount     << " |\n";
    std::cout << "| Expressions  | " << std::setw(valueWidth) << exprCount     << " |\n";
    std::cout << "| Comments     | " << std::setw(valueWidth) << commentCount  << " |\n";
    std::clog << "\n";
    std::clog << std::setprecision(3) << elapsed_seconds << " sec\n";
    std::clog << std::setprecision(3) << mlocPerSec << " MLOC/sec\n";
    return 0;
}
