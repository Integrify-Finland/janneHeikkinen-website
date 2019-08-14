import React from "react"
import { graphql } from "gatsby"

import { documentToReactComponents } from "@contentful/rich-text-react-renderer"

import Layout from "../../components/Layout"
import SEO from "../../components/SEO"
import BlogPost from "../../components/BlogPost"
import Section from "../../components/Section"

import OPTIONS from "../../helpers/rich-text-options"
import { selectImg } from "../../utilities/WPImages"
import { formatDate } from "../../utilities/FormatDate"

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
  const date = wordPressBlog
    ? formatDate(wordPressBlog.date)
    : formatDate(contentfulBlog.date)
  return (
    <Layout>
      <SEO title="blogi" />
      <div style={{ marginTop: "128px" }}>
        <Section isBlog>
          {contentfulBlog && (
            <BlogPost
              isFluid={!!contentfulBlog.entryImage}
              date={date}
              title={contentfulBlog.title}
              image={contentfulBlog.entryImage}
            >
              {renderBlogPost()}
            </BlogPost>
          )}
        </Section>
        <Section>
          {wordPressBlog && (
            <BlogPost
              isFluid={false}
              date={date}
              title={wordPressBlog.title}
              image={selectImg(wordPressBlog.id)}
            >
              <div
                className="blog-post"
                dangerouslySetInnerHTML={createMarkup()}
              ></div>
            </BlogPost>
          )}
        </Section>
      </div>
    </Layout>
  )
}

export default BlogPostTemplate

export const query = graphql`
  query($slug: String!) {
    contentfulBlog: contentfulBlogPost(id: { eq: $slug }) {
      title
      tags
      date
      entryImage {
        fluid {
          base64
          tracedSVG
          aspectRatio
          src
          srcSet
          srcWebp
          srcSetWebp
          sizes
        }
      }
      childContentfulBlogPostContentRichTextNode {
        json
      }
    }
    wordPressBlog: wordpressPost(slug: { eq: $slug }) {
      id
      title
      content
      date
      tags {
        name
      }
    }
  }
`
