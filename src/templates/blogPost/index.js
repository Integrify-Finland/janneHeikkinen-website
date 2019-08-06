import React from "react"
import { graphql } from "gatsby"
import { BLOCKS, MARKS, INLINES } from "@contentful/rich-text-types"
import { documentToReactComponents } from "@contentful/rich-text-react-renderer"

import Layout from "../../components/Layout"
import SEO from "../../components/SEO"
import OPTIONS from "../../helpers/rich-text-options"

const BlogPostTemplate = ({ data }) => {
  const { wordPressBlog, contentfulBlog } = data

  const renderBlogPost = () => {
    return documentToReactComponents(
      contentfulBlog.childContentfulBlogPostContentRichTextNode.json,
      OPTIONS
    )
  }
  const createMarkup = () => {
    return { __html: wordPressBlog.content }
  }
  const whichBlog = contentfulBlog ? contentfulBlog : wordPressBlog

  return (
    <Layout>
      <SEO title="blogi" />
      <h1>{whichBlog.title}</h1>
      {contentfulBlog &&
        contentfulBlog.tags.map((tag, i) => (
          <span
            style={{ backgroundColor: "#bada55", marginLeft: "1rem" }}
            key={i}
          >
            {tag}
          </span>
        ))}
      {contentfulBlog && renderBlogPost()}
      {wordPressBlog &&
        wordPressBlog.tags !== null &&
        wordPressBlog.tags.map((tag, i) => (
          <span
            style={{ backgroundColor: "#bada55", marginLeft: "1rem" }}
            key={i}
          >
            {tag.name}
          </span>
        ))}

      {wordPressBlog && <div dangerouslySetInnerHTML={createMarkup()}></div>}
    </Layout>
  )
}

export default BlogPostTemplate

export const query = graphql`
  query($slug: String!) {
    contentfulBlog: contentfulBlogPost(id: { eq: $slug }) {
      title
      tags
      childContentfulBlogPostContentRichTextNode {
        json
      }
    }
    wordPressBlog: wordpressPost(slug: { eq: $slug }) {
      id
      title
      content
      tags {
        name
      }
    }
  }
`
