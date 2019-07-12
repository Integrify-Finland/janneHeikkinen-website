import React from "react"
import { graphql } from "gatsby"

import Layout from "../components/Layout"
import SEO from "../components/SEO"

const Blogi = ({ data }) => {
  const { contentfulBlog, wordPressBlogs } = data
  const allBlogs = [...contentfulBlog.edges, ...wordPressBlogs.edges]

  return (
    <Layout>
      <SEO title="Blogit" />
      {allBlogs.map(({ node }) => (
        <p key={node.id}>{node.title}</p>
      ))}
    </Layout>
  )
}

export default Blogi

export const query = graphql`
  query {
    contentfulBlog: allContentfulBlogPost {
      edges {
        node {
          title
          tags
          id
        }
      }
    }
    wordPressBlogs: allWordpressPost {
      edges {
        node {
          id
          title
        }
      }
    }
  }
`
