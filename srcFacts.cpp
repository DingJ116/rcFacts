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
    Characters [pc, buffer.end()) are shifted left and new data
    is added to the rest of the buffer.

    @param pc Iterator to current position in buffer
    @param buffer Container for characters
    @param totalBytes Updated total bytes read
    @return Iterator to beginning of refilled buffer
*/
std::string::const_iterator refillBuffer(std::string::const_iterator pc, std::string& buffer, long& totalBytes) {

    // number of unprocessed characters [pc, buffer.cend())
    size_t d = std::distance(pc, buffer.cend());

    // move unprocessed characters, [pc, buffer.cend()), to start of the buffer
    std::copy(pc, buffer.cend(), buffer.begin());

    // read in whole blocks
    ssize_t numbytes = 0;
    while (((numbytes = READ(0, (void*)(buffer.data() + d), (size_t)(buffer.size() - d))) == (ssize_t) -1) &&
        (errno == EINTR)) {
    }
    // error in read
    if (numbytes == -1)
        return buffer.cend();
    // EOF
    if (numbytes == 0)
        return buffer.cend();

    // resize down to current size
    if ((std::string::size_type) (numbytes + d) < buffer.size())
        buffer.resize(numbytes + d);

    // update total number of bytes read
    totalBytes += (long) numbytes;

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
    const std::string_view XMLNS("xmlns");
    std::string url;
    int textsize = 0;
    int loc = 0;
    int expr_count = 0;
    int function_count = 0;
    int class_count = 0;
    int unit_count = 0;
    int decl_count = 0;
    int comment_count = 0;
    int depth = 0;
    long total = 0;
    bool intag = false;
    bool isArchive = false;
    std::string buffer(BUFFER_SIZE, ' ');
    std::string::const_iterator pc = buffer.cend();
    while (true) {
        if (std::distance(pc, buffer.cend()) < 5) {
            // refill buffer and adjust iterator
            pc = refillBuffer(pc, buffer, total);
            if (pc == buffer.cend())
                break;
        } else if (*pc == '<' && *std::next(pc) != '/' && *std::next(pc) != '?') {
            // parse start tag
            std::string::const_iterator endpc = std::find(pc, buffer.cend(), '>');
            if (endpc == buffer.cend()) {
                pc = refillBuffer(pc, buffer, total);
                endpc = std::find(pc, buffer.cend(), '>');
                if (endpc == buffer.cend()) {
                    std::cerr << "parser error: Incomplete element start tag\n";
                    return 1;
                }
            }
            std::advance(pc, 1);
            std::string::const_iterator pnameend = std::find_if(pc, std::next(endpc), [] (char c) { return c == '>' || isspace(c) || c == '/'; });
            if (pnameend == std::next(endpc)) {
                std::cerr << "parser error : Unterminated start tag '" << std::string_view(&(*pc), pnameend - pc) << "'\n";
                return 1;
            }
            const std::string_view qname(&(*pc), pnameend - pc);
            TRACE("Str Tag qname", qname);
            size_t colonpos = qname.find(':');
            if (colonpos == std::string::npos)
                colonpos = 0;
            const std::string_view prefix(&(*qname.cbegin()), colonpos);
            TRACE("Str Tag prefix", prefix);
            if (colonpos != 0)
                colonpos += 1;
            const std::string_view local_name(&(*qname.cbegin()) + colonpos, qname.size() - colonpos);
            TRACE("Str Tag local_name", local_name);
            if (local_name == "expr")
                ++expr_count;
            else if (local_name == "function")
                ++function_count;
            else if (local_name == "decl")
                ++decl_count;
            else if (local_name == "class")
                ++class_count;
            else if (local_name == "unit")
                ++unit_count;
            else if (local_name == "comment")
                ++comment_count;
            if (!isArchive && depth == 1 && local_name == "unit" )
                isArchive = true;
            pc = pnameend;
            pc = std::find_if_not(pc, std::next(endpc), isspace);
            intag = true;
            if (intag && *pc == '>') {
                std::advance(pc, 1);
                intag = false;
                ++depth;
            }
            if (intag && *pc == '/' && *std::next(pc) == '>') {
                std::advance(pc, 2);
                intag = false;
            }
        } else if (*pc == '<' && *std::next(pc) == '/') {
            // parse end tag
            std::string::const_iterator endpc = std::find(pc, buffer.cend(), '>');
            if (endpc == buffer.cend()) {
                pc = refillBuffer(pc, buffer, total);
                endpc = std::find(pc, buffer.cend(), '>');
                if (endpc == buffer.cend()) {
                    std::cerr << "parser error: Incomplete element end tag\n";
                    return 1;
                }
            }
            std::advance(pc, 2);
            std::string::const_iterator pnameend = std::find_if(pc, std::next(endpc), [] (char c) { return c == '>' || isspace(c); });
            if (pnameend == std::next(endpc)) {
                std::cerr << "parser error: Incomplete element end tag name\n";
                return 1;
            }
            const std::string_view qname(&(*pc), pnameend - pc);
            TRACE("End Tag qname", qname);
            size_t colonpos = qname.find(':');
            if (colonpos == std::string::npos)
                colonpos = 0;
            const std::string_view prefix(&(*qname.cbegin()), colonpos);
            TRACE("End Tag prefix", prefix);
            if (colonpos != 0)
                colonpos += 1;
            const std::string_view local_name(&(*qname.cbegin()) + colonpos, qname.size() - colonpos);
            TRACE("End Tag local_name", local_name);
            pc = std::next(endpc);
            --depth;

        } else if (*pc == '<' && *std::next(pc) == '?') {
            // parse XML declaration
            const std::string_view startXMLDecl = "<?xml";
            const std::string_view endXMLDecl = "?>";
            std::string::const_iterator endpc = std::find(pc, buffer.cend(), '>');
            if (endpc == buffer.cend()) {
                pc = refillBuffer(pc, buffer, total);
                endpc = std::find(pc, buffer.cend(), '>');
                if (endpc == buffer.cend()) {
                    std::cerr << "parser error: Incomplete XML declaration\n";
                    return 1;
                }
            }
            std::advance(pc, startXMLDecl.size());
            pc = std::find_if_not(pc, endpc, isspace);
            // parse required version
            if (pc == endpc) {
                std::cerr << "parser error: Missing space after before version in XML declaration\n";
                return 1;
            }
            std::string::const_iterator pnameend = std::find(pc, endpc, '=');
            const std::string_view attr(&(*pc), pnameend - pc);
            pc = std::next(pnameend);
            const char delim = *pc;
            if (delim != '"' && delim != '\'') {
                std::cerr << "parser error: Invalid start delimiter for version in XML declaration\n";
                return 1;
            }
            std::advance(pc, 1);
            std::string::const_iterator pvalueend = std::find(pc, endpc, delim);
            if (pvalueend == endpc) {
                std::cerr << "parser error: Invalid end delimiter for version in XML declaration\n";
                return 1;
            }
            if (attr != "version") {
                std::cerr << "parser error: Missing required first attribute version in XML declaration\n";
                return 1;
            }
            const std::string_view version(&(*pc), pvalueend - pc);
            pc = std::next(pvalueend);
            pc = std::find_if_not(pc, endpc, isspace);
            // parse optional encoding and standalone attributes
            std::optional<std::string_view> encoding;
            std::optional<std::string_view> standalone;
            if (pc != (endpc - endXMLDecl.size())) {
                pnameend = std::find(pc, endpc, '=');
                if (pnameend == endpc) {
                    std::cerr << "parser error: Incomplete attribute in XML declaration\n";
                    return 1;
                }
                const std::string_view attr2(&(*pc), pnameend - pc);
                pc = std::next(pnameend);
                char delim2 = *pc;
                if (delim2 != '"' && delim2 != '\'') {
                    std::cerr << "parser error: Invalid end delimiter for attribute " << attr2 << " in XML declaration\n";
                    return 1;
                }
                std::advance(pc, 1);
                pvalueend = std::find(pc, endpc, delim2);
                if (pvalueend == endpc) {
                    std::cerr << "parser error: Incomplete attribute " << attr2 << " in XML declaration\n";
                    return 1;
                }
                if (attr2 == "encoding") {
                    encoding = std::string_view(&(*pc), pvalueend - pc);
                } else if (attr2 == "standalone") {
                    standalone = std::string_view(&(*pc), pvalueend - pc);
                } else {
                    std::cerr << "parser error: Invalid attribute " << attr2 << " in XML declaration\n";
                    return 1;
                }
                pc = std::next(pvalueend);
                pc = std::find_if_not(pc, endpc, isspace);
            }
            if (pc != (endpc - endXMLDecl.size() + 1)) {
                pnameend = std::find(pc, endpc, '=');
                if (pnameend == endpc) {
                    std::cerr << "parser error: Incomplete attribute in XML declaration\n";
                    return 1;
                }
                const std::string_view attr2(&(*pc), pnameend - pc);
                pc = std::next(pnameend);
                char delim2 = *pc;
                if (delim2 != '"' && delim2 != '\'') {
                    std::cerr << "parser error: Invalid end delimiter for attribute " << attr2 << " in XML declaration\n";
                    return 1;
                }
                std::advance(pc, 1);
                pvalueend = std::find(pc, endpc, delim2);
                if (pvalueend == endpc) {
                    std::cerr << "parser error: Incomplete attribute " << attr2 << " in XML declaration\n";
                    return 1;
                }
                if (attr2 == "standalone" && !standalone) {
                    standalone = std::string_view(&(*pc), pvalueend - pc);
                } else {
                    std::cerr << "parser error: Invalid attribute " << attr2 << " in XML declaration\n";
                    return 1;
                }
                pc = std::next(pvalueend);
                pc = std::find_if_not(pc, endpc, isspace);
            }
            std::advance(pc, endXMLDecl.size());
            pc = std::find_if_not(pc, buffer.cend(), isspace);

        } else if (intag && *pc != '>' && *pc != '/' && std::distance(pc, buffer.cend()) > (int) XMLNS.size() && std::string_view(&(*pc), XMLNS.size()) == XMLNS
            && (*std::next(pc, XMLNS.size()) == ':' || *std::next(pc, XMLNS.size()) == '=')) {
            // parse namespace
            std::advance(pc, XMLNS.size());
            const std::string::const_iterator endpc = std::find(pc, buffer.cend(), '>');
            std::string::const_iterator pnameend = std::find(pc, std::next(endpc), '=');
            if (pnameend == std::next(endpc)) {
                std::cerr << "parser error : incomplete namespace\n";
                return 1;
            }
            int prefixSize = 0;
            if (*pc == ':') {
                std::advance(pc, 1);
                prefixSize = pnameend - pc;
            }
            const std::string_view prefix(&(*pc), prefixSize);
            pc = std::next(pnameend);
            pc = std::find_if_not(pc, std::next(endpc), isspace);
            if (pc == std::next(endpc)) {
                std::cerr << "parser error : incomplete namespace\n";
                return 1;
            }
            const char delim = *pc;
            if (delim != '"' && delim != '\'') {
                std::cerr << "parser error : incomplete namespace\n";
                return 1;
            }
            std::advance(pc, 1);
            std::string::const_iterator pvalueend = std::find(pc, std::next(endpc), delim);
            if (pvalueend == std::next(endpc)) {
                std::cerr << "parser error : incomplete namespace\n";
                return 1;
            }
            const std::string_view uri(&(*pc), pnameend - pc);
            pc = std::next(pvalueend);
            pc = std::find_if_not(pc, std::next(endpc), isspace);
            if (intag && *pc == '>') {
                std::advance(pc, 1);
                intag = false;
                ++depth;
            }
            if (intag && *pc == '/' && *std::next(pc) == '>') {
                std::advance(pc, 2);
                intag = false;
            }
        } else if (intag && *pc != '>' && *pc != '/') {
            // parse attribute
            const std::string::const_iterator endpc = std::find(pc, buffer.cend(), '>');
            std::string::const_iterator pnameend = std::find(pc, std::next(endpc), '=');
            if (pnameend == std::next(endpc))
                return 1;
            const std::string_view qname(&(*pc), pnameend - pc);
            TRACE("ATTR qname", qname);
            size_t colonpos = qname.find(':');
            if (colonpos == std::string::npos)
                colonpos = 0;
            const std::string_view prefix(&(*qname.cbegin()), colonpos);
            TRACE("ATTR prefix", prefix);
            if (colonpos != 0)
                colonpos += 1;
            const std::string_view local_name(&(*qname.cbegin()) + colonpos, qname.size() - colonpos);
            TRACE("ATTR local_name", local_name);
            pc = std::next(pnameend);
            pc = std::find_if_not(pc, std::next(endpc), isspace);
            if (pc == buffer.cend()) {
                std::cerr << "parser error : attribute " << qname << " incomplete attribute\n";
                return 1;
            }
            const char delim = *pc;
            if (delim != '"' && delim != '\'') {
                std::cerr << "parser error : attribute " << qname << " missing delimiter\n";
                return 1;
            }
            std::advance(pc, 1);
            std::string::const_iterator pvalueend = std::find(pc, std::next(endpc), delim);
            if (pvalueend == std::next(endpc)) {
                std::cerr << "parser error : attribute " << qname << " missing delimiter\n";
                return 1;
            }
            const std::string_view value(&(*pc), &(*pvalueend) - &(*pc));
            TRACE("ATTR value", value);
            if (local_name == "url")
                url = value;
            pc = std::next(pvalueend);
            pc = std::find_if_not(pc, std::next(endpc), isspace);
            if (intag && *pc == '>') {
                std::advance(pc, 1);
                intag = false;
                ++depth;
            }
            if (intag && *pc == '/' && *std::next(pc) == '>') {
                std::advance(pc, 2);
                intag = false;
            }
        } else if (*pc == '<' && *std::next(pc) == '!' && *std::next(pc, 2) == '[') {
            // parse CDATA
            const std::string_view startCDATA = "<![CDATA[";
            const std::string_view endCDATA = "]]>";
            std::advance(pc, startCDATA.size());
            std::string::const_iterator endpc = std::search(pc, buffer.cend(), endCDATA.begin(), endCDATA.end());
            if (endpc == buffer.cend()) {
                pc = refillBuffer(pc, buffer, total);
                endpc = std::search(pc, buffer.cend(), endCDATA.begin(), endCDATA.end());
                if (endpc == buffer.cend())
                    return 1;
            }
            const std::string_view characters(&(*pc), &(*endpc) - &(*pc));
            TRACE("CDATA", characters);
            textsize += (int) characters.size();
            loc += (int) std::count(characters.begin(), characters.end(), '\n');
            pc = std::next(endpc, endCDATA.size());
        } else if (*pc == '<' && *std::next(pc) == '!' && *std::next(pc, 2) == '-' && *std::next(pc, 3) == '-') {
            // parse XML comment
            const std::string_view endComment = "-->";
            std::string::const_iterator endpc = std::search(pc, buffer.cend(), endComment.begin(), endComment.end());
            if (endpc == buffer.cend()) {
                pc = refillBuffer(pc, buffer, total);
                endpc = std::search(pc, buffer.cend(), endComment.begin(), endComment.end());
                if (endpc == buffer.cend()) {
                    std::cerr << "parser error : Unterminated XML comment\n";
                    return 1;
                }
            }
            const std::string_view comment(&(*pc), endpc - pc);
            TRACE("Comment", comment);
            pc = std::next(endpc, endComment.size());
            pc = std::find_if_not(pc, buffer.cend(), isspace);
        } else if (*pc != '<' && depth == 0) {
            // parse characters before or after XML
            pc = std::find_if_not(pc, buffer.cend(), isspace);
            if (pc == buffer.cend() || !isspace(*pc)) {
                std::cerr << "parser error : Start tag expected, '<' not found\n";
                return 1;
            }
        } else if (*pc == '&') {
            // parse character entity references
            std::string_view characters;
            if (std::distance(pc, buffer.cend()) < 3) {
               pc = refillBuffer(pc, buffer, total);
               if (std::distance(pc, buffer.cend()) < 3) {
                    std::cerr << "parser error : Incomplete entity reference, '" << std::string_view(&(*pc), buffer.cend() - pc) << "'\n";
                    return 1;
               }
            }
            if (*std::next(pc) == 'l' && *std::next(pc, 2) == 't' && *std::next(pc, 3) == ';') {
                characters = "<";
                std::advance(pc, strlen("&lt;"));
            } else if (*std::next(pc) == 'g' && *std::next(pc, 2) == 't' && *std::next(pc, 3) == ';') {
                characters = ">";
                std::advance(pc, strlen("&gt;"));
            } else if (*std::next(pc) == 'a' && *std::next(pc, 2) == 'm' && *std::next(pc, 3) == 'p') {
                if (std::distance(pc, buffer.cend()) < 4) {
                    pc = refillBuffer(pc, buffer, total);
                    if (std::distance(pc, buffer.cend()) < 4) {
                        std::cerr << "parser error : Incomplete entity reference, '" << std::string_view(&(*pc), buffer.cend() - pc) << "'\n";
                        return 1;
                    }
                }
                if (*std::next(pc, 4) != ';') {
                    std::cerr << "parser error : Incomplete entity reference, '" << std::string_view(&(*pc), 4) << "'\n";
                    return 1;
                }
                characters = "&";
                std::advance(pc, strlen("&amp;"));
            } else {
                characters = "&";
                std::advance(pc, 1);
            }
            TRACE("ENTREF", characters);
            ++textsize;

        } else if (*pc != '<') {
            // parse character non-entity references
            const std::string::const_iterator endpc = std::find_if(pc, buffer.cend(), [] (char c) { return c == '<' || c == '&'; });
            const std::string_view characters(&(*pc), &(*endpc) - &(*pc));
            TRACE("Characters", characters);
            loc += (int) std::count(characters.cbegin(), characters.cend(), '\n');
            textsize += (int) characters.size();
            pc = endpc;
        }
    }
    auto finish = std::chrono::steady_clock::now();
    auto elapsed_seconds = std::chrono::duration_cast<std::chrono::duration<double> >(finish - start).count();
    double mlocPerSec = loc / elapsed_seconds / 1000000;
    int files = unit_count;
    if (isArchive)
        --files;
    std::locale cpploc{""};
    std::cout.imbue(cpploc);
    int valueWidth = std::max(5, (int)(log10(total) * 1.3 + 1));
    std::cout << "# srcFacts: " << url << '\n';
    std::cout << "| Measure      | " << std::setw(valueWidth + 3) << "Value |\n";
    std::cout << "|:-------------|-" << std::setw(valueWidth + 3) << std::setfill('-') << ":|\n" << std::setfill(' ');
    std::cout << "| srcML bytes  | " << std::setw(valueWidth) << total          << " |\n";
    std::cout << "| Characters   | " << std::setw(valueWidth) << textsize       << " |\n";
    std::cout << "| Files        | " << std::setw(valueWidth) << files          << " |\n";
    std::cout << "| LOC          | " << std::setw(valueWidth) << loc            << " |\n";
    std::cout << "| Classes      | " << std::setw(valueWidth) << class_count    << " |\n";
    std::cout << "| Functions    | " << std::setw(valueWidth) << function_count << " |\n";
    std::cout << "| Declarations | " << std::setw(valueWidth) << decl_count     << " |\n";
    std::cout << "| Expressions  | " << std::setw(valueWidth) << expr_count     << " |\n";
    std::cout << "| Comments     | " << std::setw(valueWidth) << comment_count  << " |\n";
    std::clog << "\n";
    std::clog << std::setprecision(2) << elapsed_seconds << " sec\n";
    std::clog << std::setprecision(2) << mlocPerSec << " MLOC/sec\n";
    return 0;
}
