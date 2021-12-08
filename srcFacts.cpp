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

const int BUFFER_SIZE = 16 * 16 * 4096;

/*
    Refill the buffer preserving the unused data.
    Characters [cursor, buffer.end()) are shifted left and new data
    is added to the rest of the buffer.

    @param cursor Iterator to current position in buffer
    @param buffer Container for characters
    @param totalBytes Updated total bytes read
    @return Iterator to beginning of refilled buffer
*/
std::optional<std::string::const_iterator> refillBuffer(std::string::const_iterator cursor, std::string& buffer, long& totalBytes) {

    // number of unprocessed characters [cursor, buffer.cend())
    size_t unprocessed = std::distance(cursor, buffer.cend());

    // move unprocessed characters, [cursor, buffer.cend()), to start of the buffer
    std::copy(cursor, buffer.cend(), buffer.begin());

    // read in whole blocks
    ssize_t numbytes = 0;
    while (((numbytes = READ(0, static_cast<void*>(buffer.data() + unprocessed),
        static_cast<size_t>(buffer.size() - unprocessed))) == static_cast<ssize_t>(-1)) && (errno == EINTR)) {
    }
    // error in read
    if (numbytes == -1)
        return std::nullopt;
    // EOF
    if (numbytes == 0)
        return buffer.cend();

    // resize down to current size
    if ((std::string::size_type) (numbytes + unprocessed) < buffer.size())
        buffer.resize(numbytes + unprocessed);

    // update total number of bytes read
    totalBytes += static_cast<long>(numbytes);

    // return iterator to first part of buffer
    return buffer.cbegin();
}

#ifdef TRACE
#define TRACE(m,n) std::clog << m << ": |" << n << "|\n";
#else
#define TRACE(m,n)
#endif

int main() {
    auto start = std::chrono::steady_clock::now();
    constexpr std::string_view XMLNS("xmlns");
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
    long total = 0;
    bool intag = false;
    bool isArchive = false;
    std::string buffer(BUFFER_SIZE, ' ');
    std::string::const_iterator cursor = buffer.cend();
    while (true) {
        if (std::distance(cursor, buffer.cend()) < 5) {
            // refill buffer and adjust iterator
            auto optCursor = refillBuffer(cursor, buffer, total);
            if (!optCursor) {
                std::cerr << "parser error : File input error\n";
                return 1;
            }
            cursor = *optCursor;
            if (cursor == buffer.cend())
                break;
        } else if (*cursor == '<' && *std::next(cursor) != '/' && *std::next(cursor) != '?') {
            // parse start tag
            std::string::const_iterator tagEnd = std::find(cursor, buffer.cend(), '>');
            if (tagEnd == buffer.cend()) {
                auto optCursor = refillBuffer(cursor, buffer, total);
                if (!optCursor) {
                    std::cerr << "parser error : File input error\n";
                    return 1;
                }
                cursor = *optCursor;
                tagEnd = std::find(cursor, buffer.cend(), '>');
                if (tagEnd == buffer.cend()) {
                    std::cerr << "parser error: Incomplete element start tag\n";
                    return 1;
                }
            }
            std::advance(cursor, 1);
            std::string::const_iterator nameEnd = std::find_if(cursor, std::next(tagEnd), [] (char c) { return c == '>' || isspace(c) || c == '/'; });
            if (nameEnd == std::next(tagEnd)) {
                std::cerr << "parser error : Unterminated start tag '" << std::string_view(std::addressof(*cursor), std::distance(cursor, nameEnd)) << "'\n";
                return 1;
            }
            const std::string_view qName(std::addressof(*cursor), std::distance(cursor, nameEnd));
            TRACE("Str Tag qName", qName);
            size_t colonPosition = qName.find(':');
            if (colonPosition == std::string::npos)
                colonPosition = 0;
            const std::string_view prefix(std::addressof(*qName.cbegin()), colonPosition);
            TRACE("Str Tag prefix", prefix);
            if (colonPosition != 0)
                colonPosition += 1;
            const std::string_view localName(std::addressof(*qName.cbegin()) + colonPosition, qName.size() - colonPosition);
            TRACE("Str Tag localName", localName);
            if (localName == "expr")
                ++exprCount;
            else if (localName == "function")
                ++functionCount;
            else if (localName == "decl")
                ++declCount;
            else if (localName == "class")
                ++classCount;
            else if (localName == "unit")
                ++unitCount;
            else if (localName == "comment")
                ++commentCount;
            if (!isArchive && depth == 1 && localName == "unit" )
                isArchive = true;
            cursor = nameEnd;
            cursor = std::find_if_not(cursor, std::next(tagEnd), isspace);
            intag = true;
            if (intag && *cursor == '>') {
                std::advance(cursor, 1);
                intag = false;
                ++depth;
            }
            if (intag && *cursor == '/' && *std::next(cursor) == '>') {
                std::advance(cursor, 2);
                intag = false;
            }
        } else if (*std::next(cursor) == '/' && *cursor == '<') {
            // parse end tag
            std::string::const_iterator tagEnd = std::find(cursor, buffer.cend(), '>');
            if (tagEnd == buffer.cend()) {
                auto optCursor = refillBuffer(cursor, buffer, total);
                if (!optCursor) {
                    std::cerr << "parser error : File input error\n";
                    return 1;
                }
                cursor = *optCursor;
                tagEnd = std::find(cursor, buffer.cend(), '>');
                if (tagEnd == buffer.cend()) {
                    std::cerr << "parser error: Incomplete element end tag\n";
                    return 1;
                }
            }
            std::advance(cursor, 2);
            std::string::const_iterator nameEnd = std::find_if(cursor, std::next(tagEnd), [] (char c) { return c == '>' || isspace(c); });
            if (nameEnd == std::next(tagEnd)) {
                std::cerr << "parser error: Incomplete element end tag name\n";
                return 1;
            }
            const std::string_view qName(std::addressof(*cursor), std::distance(cursor, nameEnd));
            TRACE("End Tag qName", qName);
            size_t colonPosition = qName.find(':');
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

        } else if (*std::next(cursor) == '?' && *cursor == '<') {
            // parse XML declaration
            constexpr std::string_view startXMLDecl = "<?xml";
            constexpr std::string_view endXMLDecl = "?>";
            std::string::const_iterator tagEnd = std::find(cursor, buffer.cend(), '>');
            if (tagEnd == buffer.cend()) {
                auto optCursor = refillBuffer(cursor, buffer, total);
                if (!optCursor) {
                    std::cerr << "parser error : File input error\n";
                    return 1;
                }
                cursor = *optCursor;
                tagEnd = std::find(cursor, buffer.cend(), '>');
                if (tagEnd == buffer.cend()) {
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
            if (attr != "version") {
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
                if (attr2 == "encoding") {
                    encoding = std::string_view(std::addressof(*cursor), std::distance(cursor, valueEnd));
                } else if (attr2 == "standalone") {
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
                if (attr2 == "standalone" && !standalone) {
                    standalone = std::string_view(std::addressof(*cursor), std::distance(cursor, valueEnd));
                } else {
                    std::cerr << "parser error: Invalid attribute " << attr2 << " in XML declaration\n";
                    return 1;
                }
                cursor = std::next(valueEnd);
                cursor = std::find_if_not(cursor, tagEnd, isspace);
            }
            std::advance(cursor, endXMLDecl.size());
            cursor = std::find_if_not(cursor, buffer.cend(), isspace);

        } else if (intag && std::distance(cursor, buffer.cend()) > static_cast<int>(XMLNS.size()) && std::string_view(std::addressof(*cursor), XMLNS.size()) == XMLNS
            && (*std::next(cursor, XMLNS.size()) == ':' || *std::next(cursor, XMLNS.size()) == '=')) {
            // parse namespace
            std::advance(cursor, XMLNS.size());
            const std::string::const_iterator tagEnd = std::find(cursor, buffer.cend(), '>');
            std::string::const_iterator nameEnd = std::find(cursor, std::next(tagEnd), '=');
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
            std::string::const_iterator valueEnd = std::find(cursor, std::next(tagEnd), delimiter);
            if (valueEnd == std::next(tagEnd)) {
                std::cerr << "parser error : incomplete namespace\n";
                return 1;
            }
            const std::string_view uri(std::addressof(*cursor), std::distance(cursor, nameEnd));
            cursor = std::next(valueEnd);
            cursor = std::find_if_not(cursor, std::next(tagEnd), isspace);
            if (intag && *cursor == '>') {
                std::advance(cursor, 1);
                intag = false;
                ++depth;
            }
            if (intag && *cursor == '/' && *std::next(cursor) == '>') {
                std::advance(cursor, 2);
                intag = false;
            }
        } else if (intag) {
            // parse attribute
            const std::string::const_iterator tagEnd = std::find(cursor, buffer.cend(), '>');
            std::string::const_iterator nameEnd = std::find(cursor, std::next(tagEnd), '=');
            if (nameEnd == std::next(tagEnd))
                return 1;
            const std::string_view qName(std::addressof(*cursor), std::distance(cursor, nameEnd));
            TRACE("ATTR qName", qName);
            size_t colonPosition = qName.find(':');
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
            if (cursor == buffer.cend()) {
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
            if (localName == "url")
                url = value;
            cursor = std::next(valueEnd);
            cursor = std::find_if_not(cursor, std::next(tagEnd), isspace);
            if (intag && *cursor == '>') {
                std::advance(cursor, 1);
                intag = false;
                ++depth;
            }
            if (intag && *cursor == '/' && *std::next(cursor) == '>') {
                std::advance(cursor, 2);
                intag = false;
            }
        } else if (*std::next(cursor) == '!' && *cursor == '<' && *std::next(cursor, 2) == '[') {
            // parse CDATA
            constexpr std::string_view startCDATA = "<![CDATA[";
            constexpr std::string_view endCDATA = "]]>";
            std::advance(cursor, startCDATA.size());
            std::string::const_iterator tagEnd = std::search(cursor, buffer.cend(), endCDATA.begin(), endCDATA.end());
            if (tagEnd == buffer.cend()) {
                auto optCursor = refillBuffer(cursor, buffer, total);
                if (!optCursor) {
                    std::cerr << "parser error : File input error\n";
                    return 1;
                }
                cursor = *optCursor;
                tagEnd = std::search(cursor, buffer.cend(), endCDATA.begin(), endCDATA.end());
                if (tagEnd == buffer.cend())
                    return 1;
            }
            const std::string_view characters(std::addressof(*cursor), std::distance(cursor, tagEnd));
            TRACE("CDATA", characters);
            textsize += static_cast<int>(characters.size());
            loc += static_cast<int>(std::count(characters.begin(), characters.end(), '\n'));
            cursor = std::next(tagEnd, endCDATA.size());
        } else if (*std::next(cursor) == '!' && *cursor == '<' && *std::next(cursor, 2) == '-' && *std::next(cursor, 3) == '-') {
            // parse XML comment
            constexpr std::string_view endComment = "-->";
            std::string::const_iterator tagEnd = std::search(cursor, buffer.cend(), endComment.begin(), endComment.end());
            if (tagEnd == buffer.cend()) {
                auto optCursor = refillBuffer(cursor, buffer, total);
                if (!optCursor) {
                    std::cerr << "parser error : File input error\n";
                    return 1;
                }
                cursor = *optCursor;
                tagEnd = std::search(cursor, buffer.cend(), endComment.begin(), endComment.end());
                if (tagEnd == buffer.cend()) {
                    std::cerr << "parser error : Unterminated XML comment\n";
                    return 1;
                }
            }
            const std::string_view comment(std::addressof(*cursor), std::distance(cursor, tagEnd));
            TRACE("Comment", comment);
            cursor = std::next(tagEnd, endComment.size());
            cursor = std::find_if_not(cursor, buffer.cend(), isspace);
        } else if (depth == 0 && *cursor != '<') {
            // parse characters before or after XML
            cursor = std::find_if_not(cursor, buffer.cend(), isspace);
            if (cursor == buffer.cend() || !isspace(*cursor)) {
                std::cerr << "parser error : Start tag expected, '<' not found\n";
                return 1;
            }
        } else if (*cursor == '&') {
            // parse character entity references
            std::string_view characters;
            // if (std::distance(cursor, buffer.cend()) < 3) {
            //    cursor = refillBuffer(cursor, buffer, total);
            //    if (std::distance(cursor, buffer.cend()) < 3) {
            //         std::cerr << "parser error : Incomplete entity reference, '" << std::string_view(std::addressof(*cursor), std::distance(cursor, buffer.cend())) << "'\n";
            //         return 1;
            //    }
            // }
            constexpr std::string_view LT = "&lt;";
            constexpr std::string_view GT = "&gt;";
            constexpr std::string_view AMP = "&amp;";
            if (std::string_view(std::addressof(*cursor), LT.size()) == LT) {
                characters = "<";
                std::advance(cursor, LT.size());
            } else if (std::string_view(std::addressof(*cursor), GT.size()) == GT) {
                characters = ">";
                std::advance(cursor, GT.size());
            } else if (std::string_view(std::addressof(*cursor), AMP.size()) == AMP) {
                characters = "&";
                std::advance(cursor, AMP.size());
            } else {
                characters = "&";
                std::advance(cursor, 1);
            }
            TRACE("ENTREF", characters);
            ++textsize;

        } else {
            // parse character non-entity references
            const std::string::const_iterator tagEnd = std::find_if(cursor, buffer.cend(), [] (char c) { return c == '<' || c == '&'; });
            const std::string_view characters(std::addressof(*cursor), std::distance(cursor, tagEnd));
            TRACE("Characters", characters);
            loc += static_cast<int>(std::count(characters.cbegin(), characters.cend(), '\n'));
            textsize += static_cast<int>(characters.size());
            cursor = tagEnd;
        }
    }
    auto finish = std::chrono::steady_clock::now();
    auto elapsed_seconds = std::chrono::duration_cast<std::chrono::duration<double> >(finish - start).count();
    double mlocPerSec = loc / elapsed_seconds / 1000000;
    int files = unitCount;
    if (isArchive)
        --files;
    std::locale cpploc{""};
    std::cout.imbue(cpploc);
    int valueWidth = std::max(5, static_cast<int>(log10(total) * 1.3 + 1));
    std::cout << "# srcFacts: " << url << '\n';
    std::cout << "| Measure      | " << std::setw(valueWidth + 3) << "Value |\n";
    std::cout << "|:-------------|-" << std::setw(valueWidth + 3) << std::setfill('-') << ":|\n" << std::setfill(' ');
    std::cout << "| srcML bytes  | " << std::setw(valueWidth) << total          << " |\n";
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
