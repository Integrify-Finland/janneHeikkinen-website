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
import { WPContent } from "../../utilities/WPblogs.js"

const BlogPostTemplate = ({ data, location }) => {
  const { contentfulBlog } = data
  const currentBlog = WPContent.edges
    .filter(({ node }) => `/blogi/${node.slug}` === location.pathname)
    .map(blog => blog.node)[0]

  const renderBlogPost = () => {
    return documentToReactComponents(
      contentfulBlog.childContentfulBlogPostContentRichTextNode.json,
      OPTIONS
    )
  }
  const createMarkup = () => {
    return { __html: currentBlog.content }
  }
  const whichBlog = contentfulBlog ? contentfulBlog : currentBlog
  const date = currentBlog
    ? formatDate(currentBlog.date)
    : formatDate(contentfulBlog.date)
  return (
    <Layout>
      <div style={{ paddingTop: "128px", backgroundColor: "#edf5f8" }}>
        <SEO title="blogi" />
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
          {currentBlog && (
            <BlogPost
              isFluid={false}
              date={date}
              title={currentBlog.title}
              image={selectImg(currentBlog.id)}
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
  }
`
