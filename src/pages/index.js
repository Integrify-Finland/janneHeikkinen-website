import React from "react"
import { graphql } from "gatsby"
import { BLOCKS, MARKS } from "@contentful/rich-text-types"
import { documentToReactComponents } from "@contentful/rich-text-react-renderer"

import Layout from "../components/Layout"
import Image from "../components/Image"
import SEO from "../components/SEO"

// these are UI components for customising the blog posts from contentful
const Bold = ({ children }) => <span className="bold">{children}</span>
const Text = ({ children }) => <p className="custom-class">{children}</p>
const ULlists = ({ children }) => <ul className="custom-class">{children}</ul>

const IndexPage = ({ data }) => {
  const { aboutMe, wordPressBlogs, youTubeVid, blogPost } = data
  const options = {
    renderMark: {
      [MARKS.BOLD]: text => <Bold>{text}</Bold>,
    },
    renderNode: {
      [BLOCKS.PARAGRAPH]: (node, children) => <Text>{children}</Text>,
    },
    renderNode: {
      [BLOCKS.UL_LIST]: (node, children) => <ULlists>{children}</ULlists>,
    },
  }

  const renderBlogPost = () => {
    return documentToReactComponents(
      blogPost.childContentfulBlogPostContentRichTextNode.json,
      options
    )
  }

  return (
    <Layout>
      <SEO title="Home" />
      <h1>{aboutMe.title}</h1>
      <p>{aboutMe.description}</p>
      <div style={{ maxWidth: `300px`, marginTop: `10rem` }}>
        <Image />
      </div>
      {renderBlogPost()}
    </Layout>
  )
}

export default IndexPage

export const query = graphql`
  query {
    aboutMe: contentfulAboutMe {
      id
      title
      description
    }
    youTubeVid: allYoutubeVideo {
      edges {
        node {
          id
          title
          description
          videoId
          publishedAt
          privacyStatus
          channelTitle
        }
      }
    }
    wordPressBlogs: allWordpressPost {
      edges {
        node {
          id
          title
          tags {
            name
          }
        }
      }
    }
    blogPost: contentfulBlogPost {
      childContentfulBlogPostContentRichTextNode {
        json
      }
    }
  }
`
