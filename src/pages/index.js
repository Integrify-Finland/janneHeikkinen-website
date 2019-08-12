import React, { useState } from "react"
import { graphql } from "gatsby"
import { switchToNums, switchToCat } from "../utilities/switches"
import BlogItem from "../components/BlogItem"
import Layout from "../components/Layout"
import SEO from "../components/SEO"
import SocialMedia from "../components/SocialMedia/index"
import Section from "../components/Section"
import image from "../images/JANNE_HEIKKINEN_260619_77.jpg"
import Header from "../components/Header"

const Blog = ({ data }) => {
  const { contentfulBlog, wordPressBlogs } = data
  const [currentPage, setCurrentPage] = useState(1)
  const [postsPerPage] = useState(3)
  const indexOfLastPost = currentPage * postsPerPage
  const indexOfFirstPost = indexOfLastPost - postsPerPage
  const allBlogs = [...contentfulBlog.edges, ...wordPressBlogs.edges]
  const [chosenBlogs, setChosenBlogs] = useState(allBlogs)

  const text =
    "Julkaistu alun perin Kalevassa 5.6.2019 Minun ei käy kateeksi näinä päivinä suomalaista pienyrittäjää. Heidän äänensä ei ole liiemmin kuulunut viime viikkoina säätytalolla. Sen sijaan tulevan hallituksen ohjelmaa ovat olleet kunniavieraina kirjoittamassa kansainvälisten suuryritysten ja etujärjestöjen palkkaamat lobbaustoimistot. Ikävä kyllä pienyrittäjillä ei ole vastaavaa taloudellista mahdollisuutta kalliisiin"
  const shortText = text.substr(0, 416) + "..."

  return (
    <div style={{ display: "flex" }}>
      <Section>
        {chosenBlogs
          .map((blog, i) => ({
            blog,
            number: i + 1,
          }))
          .slice(indexOfFirstPost, indexOfLastPost)
          .map(({ blog, number }) => {
            const link = blog.node ? blog.node.slug : blog.slug
            return (
              <BlogItem
                date="5.6.2018"
                title={blog.node ? blog.node.title : blog.title}
                number={number}
                image={image}
                text={shortText}
                link={`blogi/${link
                  .toLowerCase()
                  .replace(/[']/gi, "")
                  .replace(/ /gi, "-")
                  .replace(/[,]/gi, "")
                  .replace(/[ä]/gi, "a")
                  .replace(/[ö]/gi, "o")}`}
              />
            )
          })}
      </Section>
    </div>
  )
}

const IndexPage = ({ data }) => {
  return (
    <Layout>
      <Header isAbout={false} />
      <Section>
        <SEO title="Home" />
        <h1
          style={{
            textAlign: "center",
            color: "#023b56",
            fontSize: "64px",
            fontWeight: "400",
            textDecoration: "underline #6ccff6",
          }}
        >
          Blogi
        </h1>
      </Section>
      <Blog data={data} />
      <Section>
        <SocialMedia />
      </Section>
    </Layout>
  )
}

export default IndexPage

export const query = graphql`
  query {
    contentfulBlog: allContentfulBlogPost {
      edges {
        node {
          title
          tags
          categories
          id
          slug
          date
        }
      }
    }
    wordPressBlogs: allWordpressPost {
      edges {
        node {
          id
          categories
          title
          slug
          date
          tags {
            name
          }
        }
      }
    }
  }
`
