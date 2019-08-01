import React, { useState } from "react"
import { graphql, Link } from "gatsby"

import Layout from "../components/Layout"
import BlogItem from "../components/BlogItem"
import SEO from "../components/SEO"
import Pagination from "../components/Pagination"
import Section from "../components/Section"

import image from "../images/JANNE_HEIKKINEN_260619_77.jpg"

const Blogi = ({ data }) => {
  const { contentfulBlog, wordPressBlogs } = data

  const [currentPage, setCurrentPage] = useState(1)
  const [postsPerPage] = useState(15)

  const allBlogs = [...contentfulBlog.edges, ...wordPressBlogs.edges]

  const indexOfLastPost = currentPage * postsPerPage
  const indexOfFirstPost = indexOfLastPost - postsPerPage

  const paginate = pageNumber => setCurrentPage(pageNumber)

  const text =
    "Julkaistu alun perin Kalevassa 5.6.2019 Minun ei käy kateeksi näinä päivinä suomalaista pienyrittäjää. Heidän äänensä ei ole liiemmin kuulunut viime viikkoina säätytalolla. Sen sijaan tulevan hallituksen ohjelmaa ovat olleet kunniavieraina kirjoittamassa kansainvälisten suuryritysten ja etujärjestöjen palkkaamat lobbaustoimistot. Ikävä kyllä pienyrittäjillä ei ole vastaavaa taloudellista mahdollisuutta kalliisiin"
  const shortText = text.substr(0, 416) + "..."

  // <Link
  //         to={`blogi/${node.slug
  //           .toLowerCase()
  //           .replace(/[']/gi, "")
  //           .replace(/ /gi, "-")
  //           .replace(/[,]/gi, "")
  //           .replace(/[ä]/gi, "a")
  //           .replace(/[ö]/gi, "o")}`}
  //         key={node.id}
  //         style={{ display: "block" }}
  //       >
  //         {node.title}
  //       </Link>

  return (
    <Layout>
      <SEO title="Blogit" />
      <Section>
        {allBlogs
          .map((blog, i) => ({
            blog,
            number: i + 1,
          }))
          .slice(indexOfFirstPost, indexOfLastPost)
          .map(({ blog, number }) => (
            <BlogItem
              date="5.6.2018"
              title={blog.node.title}
              number={number}
              image={image}
              text={shortText}
              link={`blogi/${blog.node.slug
                .toLowerCase()
                .replace(/[']/gi, "")
                .replace(/ /gi, "-")
                .replace(/[,]/gi, "")
                .replace(/[ä]/gi, "a")
                .replace(/[ö]/gi, "o")}`}
            />
          ))}
        <Pagination
          postsPerPage={postsPerPage}
          totalPosts={allBlogs.length}
          paginate={paginate}
          currentPage={currentPage}
        />
      </Section>
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
