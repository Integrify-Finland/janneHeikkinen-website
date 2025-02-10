import React from "react"
import { graphql } from "gatsby"

import BlogItem from "../components/BlogItem"
import Layout from "../components/Layout"
import SEO from "../components/SEO"
import SocialMedia from "../components/SocialMedia/index"
import Section from "../components/Section"
import image from "../images/JANNE_HEIKKINEN_260619_77.jpg"
import Header from "../components/Header"
import { WPContent } from "../utilities/WPblogs.js"
import { selectImg } from "../utilities/WPImages"
import { formatDate } from "../utilities/FormatDate"

const IndexPage = ({ data }) => {
  console.log("Home page")

  const { contentfulBlog } = data
  const allBlogs = [...contentfulBlog.edges, ...WPContent.edges]

  return (
    <Layout>
      <SEO title="Etusivu" />
      <Header
        isAbout={false}
        Subtext={
          "Kansanedustaja, yhteiskuntatieteiden maisteri ja intohimoinen perhokalastaja."
        }
      />
      <div className="index-page-wrapper">
        <Section>
          <h1 className="index-page-wrapper__title">Blogi</h1>
        </Section>
        <Section>
          {allBlogs
            .slice(0, 3)
            .map((blog, i) => ({
              blog,
              number: i + 1,
            }))
            .map(({ blog, number }, index) => {
              const img = blog.node.entryImage
                ? blog.node.entryImage
                : selectImg(blog.node.id, image)
              const date = formatDate(blog.node.date)

              const text = blog.node.entryImage
                ? blog.node.entryDescription.entryDescription
                : blog.node.content
              return (
                <BlogItem
                  isFluid={!!blog.node.entryImage}
                  date={date}
                  title={blog.node.title}
                  number={number}
                  image={img}
                  isContentful={!!blog.node.entryImage}
                  text={text}
                  link={`blogi/${blog.node.slug
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
        <Section>
          <SocialMedia />
        </Section>
      </div>
    </Layout>
  )
}

export default IndexPage

export const query = graphql`
  query {
    contentfulBlog: allContentfulBlogPost(
      sort: { fields: [createdAt], order: DESC }
    ) {
      edges {
        node {
          title
          tags
          entryDescription {
            entryDescription
          }
          body {
            childMarkdownRemark {
              html
            }
          }
          categories
          id
          slug
          date
          entryImage {
            fluid {
              base64
              aspectRatio
              src
              srcSet
              srcWebp
              srcSetWebp
              sizes
            }
          }
        }
      }
    }
  }
`
