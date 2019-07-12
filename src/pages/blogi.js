import React, { useState } from "react"
import { graphql } from "gatsby"

import Layout from "../components/Layout"
import SEO from "../components/SEO"
import Pagination from "../components/Pagination"

const Blogi = ({ data }) => {
  const { contentfulBlog, wordPressBlogs } = data

  const [currentPage, setCurrentPage] = useState(1)
  const [postsPerPage] = useState(4)

  const allBlogs = [...contentfulBlog.edges, ...wordPressBlogs.edges]

  const indexOfLastPost = currentPage * postsPerPage
  const indexOfFirstPost = indexOfLastPost - postsPerPage

  const paginate = pageNumber => setCurrentPage(pageNumber)

  return (
    <Layout>
      <SEO title="Blogit" />
      {allBlogs.slice(indexOfFirstPost, indexOfLastPost).map(({ node }) => (
        <p key={node.id}>{node.title}</p>
      ))}
      <Pagination
        postsPerPage={postsPerPage}
        totalPosts={allBlogs.length}
        paginate={paginate}
        currentPage={currentPage}
      />
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
