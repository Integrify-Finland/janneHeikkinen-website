import React, { useState } from "react"
import { graphql, Link } from "gatsby"

import Layout from "../components/Layout"
import SEO from "../components/SEO"
import Pagination from "../components/Pagination"

const Blogi = ({ data }) => {
  const { contentfulBlog, wordPressBlogs } = data

  const [currentPage, setCurrentPage] = useState(1)
  const [postsPerPage] = useState(15)

  const allBlogs = [...contentfulBlog.edges, ...wordPressBlogs.edges]

  const indexOfLastPost = currentPage * postsPerPage
  const indexOfFirstPost = indexOfLastPost - postsPerPage

  const paginate = pageNumber => setCurrentPage(pageNumber)

  return (
    <Layout>
      <SEO title="Blogit" />
      {allBlogs.slice(indexOfFirstPost, indexOfLastPost).map(({ node }) => (
        <Link
          to={`blogi/${node.slug
            .toLowerCase()
            .replace(/[']/gi, "")
            .replace(/ /gi, "-")
            .replace(/[,]/gi, "")
            .replace(/[ä]/gi, "a")
            .replace(/[ö]/gi, "o")}`}
          key={node.id}
          style={{ display: "block" }}
        >
          {node.title}
        </Link>
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
          slug
        }
      }
    }
    wordPressBlogs: allWordpressPost {
      edges {
        node {
          id
          title
          slug
        }
      }
    }
  }
`
