/*
 * schema.c: a libFuzzer target to test the XML Schema processor.
 *
 * See Copyright for the status of this software.
 */

 #ifndef XML_DEPRECATED
 #define XML_DEPRECATED
#include "libxml/xmlmemory.h"
#include "libxml/xmlreader.h"
#endif

#include <libxml/catalog.h>
#include <libxml/xmlschemas.h>
#include <libxml/xmlschemastypes.h>
#include "fuzz.h"

#include <stdbool.h>

int
LLVMFuzzerInitialize(int *argc ATTRIBUTE_UNUSED,
                    char ***argv ATTRIBUTE_UNUSED) {
   xmlFuzzMemSetup();
   xmlInitParser();
#ifdef LIBXML_CATALOG_ENABLED
   xmlInitializeCatalog();
   xmlCatalogSetDefaults(XML_CATA_ALLOW_NONE);
#endif

   return 0;
}

int
FuzzerTestOneInputInternal(const char *data, size_t size, bool useReader) {
   xmlSchemaParserCtxtPtr pctxt;
   xmlSchemaPtr schema;
   size_t failurePos;

   if (size > 200000)
       return(0);

   xmlFuzzDataInit(data, size);

   failurePos = xmlFuzzReadInt(4) % (size + 100);

   xmlFuzzReadEntities();

   xmlFuzzInjectFailure(failurePos);
   pctxt = xmlSchemaNewParserCtxt(xmlFuzzMainUrl());
   xmlSchemaSetParserStructuredErrors(pctxt, xmlFuzzSErrorFunc, NULL);
   xmlSchemaSetResourceLoader(pctxt, xmlFuzzResourceLoader, NULL);
   schema = xmlSchemaParse(pctxt);
   xmlSchemaFreeParserCtxt(pctxt);

   if (schema != NULL) {
       xmlSchemaValidCtxtPtr vctxt;
       xmlParserCtxtPtr ctxt;
       xmlDocPtr doc;
       xmlTextReaderPtr reader;

       ctxt = xmlNewParserCtxt();
       xmlCtxtSetErrorHandler(ctxt, xmlFuzzSErrorFunc, NULL);
       xmlCtxtSetResourceLoader(ctxt, xmlFuzzResourceLoader, NULL);
       doc = xmlCtxtReadFile(ctxt, xmlFuzzSecondaryUrl(), NULL,
                             XML_PARSE_NOENT);

       if (useReader) {
           reader = xmlReaderWalker(doc);
       }

       vctxt = xmlSchemaNewValidCtxt(schema);
       xmlSchemaSetValidStructuredErrors(vctxt, xmlFuzzSErrorFunc, NULL);
       if (useReader) {
           xmlSchemaValidateDoc(vctxt, doc);
       } else {
           xmlTextReaderSchemaValidateCtxt(reader, vctxt, 0);
       }
       xmlSchemaFreeValidCtxt(vctxt);

       if (useReader) {
           xmlFreeTextReader(reader);
       }
       xmlFreeDoc(doc);
       xmlSchemaFree(schema);
       xmlFreeParserCtxt(ctxt);
   }

   xmlFuzzInjectFailure(0);
   xmlFuzzDataCleanup();
   xmlResetLastError();
   xmlSchemaCleanupTypes();

   return(0);
}

int
LLVMFuzzerTestOneInput(const char *data, size_t size) {
   FuzzerTestOneInputInternal(data, size, true);
   return FuzzerTestOneInputInternal(data, size, false);
}

size_t
LLVMFuzzerCustomMutator(char *data, size_t size, size_t maxSize,
                       unsigned seed) {
   static const xmlFuzzChunkDesc chunks[] = {
       { 4, XML_FUZZ_PROB_ONE / 10 }, /* failurePos */
       { 0, 0 }
   };

   return xmlFuzzMutateChunks(chunks, data, size, maxSize, seed,
                              LLVMFuzzerMutate);
}

