import React from "react"
import { BLOCKS, MARKS, INLINES } from "@contentful/rich-text-types"
import {
  Bold,
  Italic,
  Underline,
  H1,
  H2,
  H3,
  H4,
  H5,
  H6,
  OlLists,
  Paragraph,
  UlLists,
  QUOTE,
  HR,
  HYPERLINK,
  Image,
} from "../components/HTMLelements"

const OPTIONS = {
  
  renderMark: {
    [MARKS.BOLD]: text => <Bold>{text}</Bold>,
    [MARKS.ITALIC]: text => <Italic>{text}</Italic>,
    [MARKS.UNDERLINE]: text => <Underline>{text}</Underline>,
  },

  renderNode: {
    [BLOCKS.HEADING_1]: (node, children) => <H1>{children}</H1>,
    [BLOCKS.HEADING_2]: (node, children) => <H2>{children}</H2>,
    [BLOCKS.HEADING_3]: (node, children) => <H3>{children}</H3>,
    [BLOCKS.HEADING_4]: (node, children) => <H4>{children}</H4>,
    [BLOCKS.HEADING_5]: (node, children) => <H5>{children}</H5>,
    [BLOCKS.HEADING_6]: (node, children) => <H6>{children}</H6>,
    [BLOCKS.PARAGRAPH]: (node, children) => <Paragraph>{children}</Paragraph>,
    [BLOCKS.UL_LIST]: (node, children) => <UlLists>{children}</UlLists>,
    [BLOCKS.OL_LIST]: (node, children) => <OlLists>{children}</OlLists>,
    [BLOCKS.QUOTE]: (node, children) => <QUOTE>{children}</QUOTE>,
    [BLOCKS.HR]: (node, children) => <HR>{children}</HR>,
    [BLOCKS.EMBEDDED_ASSET]: (node, children) => (
      <Image url={node.data.target.fields.file["fi-FI"].url}>{children}</Image>
    ),
    [INLINES.HYPERLINK]: (node, children) => <HYPERLINK>{children}</HYPERLINK>,
  },
}




export const OPTIONSblogi = {

  

  renderNode: {
    [BLOCKS.HEADING_1]: (node, children) => null,
    [BLOCKS.HEADING_2]: (node, children) => null,
    [BLOCKS.HEADING_3]: (node, children) => null,
    [BLOCKS.HEADING_4]: (node, children) => null,
    [BLOCKS.HEADING_5]: (node, children) => null,
    [BLOCKS.HEADING_6]: (node, children) => null,
    [BLOCKS.PARAGRAPH]: (node, children) => <Paragraph>{children}</Paragraph>,
    [BLOCKS.UL_LIST]: (node, children) => null,
    [BLOCKS.OL_LIST]: (node, children) => null,
    [BLOCKS.QUOTE]: (node, children) => null,
    [BLOCKS.HR]: (node, children) => null,
    [BLOCKS.EMBEDDED_ASSET]: (node, children) => null,
    [INLINES.HYPERLINK]: (node, children) => null,
  },
}


export default OPTIONS
