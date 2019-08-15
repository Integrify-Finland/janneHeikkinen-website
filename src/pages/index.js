import React from "react"
import { graphql } from "gatsby"

import BlogItem from "../components/BlogItem"
import Layout from "../components/Layout"
import SEO from "../components/SEO"
import SocialMedia from "../components/SocialMedia/index"
import Section from "../components/Section"
import image from "../images/JANNE_HEIKKINEN_260619_77.jpg"
import Header from "../components/Header"
import { WP } from "../utilities/WPblogs.js"
import { selectImg } from "../utilities/WPImages"
import { formatDate } from "../utilities/FormatDate"

const text =
  "Julkaistu alun perin Kalevassa 5.6.2019 Minun ei käy kateeksi näinä päivinä suomalaista pienyrittäjää. Heidän äänensä ei ole liiemmin kuulunut viime viikkoina säätytalolla. Sen sijaan tulevan hallituksen ohjelmaa ovat olleet kunniavieraina kirjoittamassa kansainvälisten suuryritysten ja etujärjestöjen palkkaamat lobbaustoimistot. Ikävä kyllä pienyrittäjillä ei ole vastaavaa taloudellista mahdollisuutta kalliisiin"
const shortText = text.substr(0, 416) + "..."

const IndexPage = ({ data }) => {
  const { contentfulBlog } = data
  const allBlogs = [...contentfulBlog.edges, ...WP.edges]

  return (
    <Layout>
      <Header
        isAbout={false}
        Subtext={
          "Kansanedustaja, yhteiskuntatieteiden maisteri ja intohimoinen perhokalastaja."
        }
      />
      <div className="index-page-wrapper">
        <Section>
          <SEO title="Home" />
          <h1 className="index-page-wrapper__title">Blogi</h1>
        </Section>
        <Section>
          {allBlogs.slice(0, 3).map(({ node }, index) => {
            const img = node.entryImage
              ? node.entryImage
              : selectImg(node.id, image)
            const date = formatDate(node.date)
            return (
              <BlogItem
                isFluid={!!node.entryImage}
                date={date}
                title={node.title}
                number={index + 1}
                image={img}
                text={shortText}
                link={`blogi/${node.slug
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
    contentfulBlog: allContentfulBlogPost {
      edges {
        node {
          title
          tags
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
