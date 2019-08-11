import React from "react"
import { graphql } from "gatsby"
import { BLOCKS, MARKS } from "@contentful/rich-text-types"
import { documentToReactComponents } from "@contentful/rich-text-react-renderer"
import Blogi from "./blogi"

import Layout from "../components/Layout"
import SEO from "../components/SEO"
import SocialMedia from '../components/SocialMedia/index'
import Section from "../components/Section"

// these are UI components for customising the blog posts from contentful
const Bold = ({ children }) => <span className="bold">{children}</span>
const Text = ({ children }) => <p className="custom-class">{children}</p>
const ULlists = ({ children }) => <ul className="custom-class">{children}</ul>



const IndexPage = ({ data }) => {
  const { blogPost } = data

  const options = {
    renderMark: {
      [MARKS.BOLD]: text => <Bold>{text}</Bold>,
    },
    renderNode: {
      [BLOCKS.PARAGRAPH]: (node, children) => <Text>{children}</Text>,
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
      <Section>
      <SEO title="Home" />
          <h1>{blogPost.title}</h1>
      <span>Tags are: </span>
      {blogPost.tags.map((tag, i) => (
        <>
          <span
            style={{ backgroundColor: "#bada55", marginLeft: "1rem" }}
            key={i}
          >
            {tag}
          </span>
        </>
      ))}
      {renderBlogPost()}
      </Section>
<Section>
      <SocialMedia />
      </Section>
    </Layout>
  )
}

export default IndexPage

export const query = graphql`
  query {
    blogPost: contentfulBlogPost {
      title
      tags
      childContentfulBlogPostContentRichTextNode {
        json
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
    
  }
`
