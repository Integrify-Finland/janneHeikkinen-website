import React from "react"
import { graphql } from "gatsby"
import Helmet from "react-helmet"
import Layout from "../../components/Layout"
import SEO from "../../components/SEO"
import BlogPost from "../../components/BlogPost"
import Section from "../../components/Section"

import { selectImg } from "../../utilities/WPImages"
import { formatDate } from "../../utilities/FormatDate"
import { WPContent, WP } from "../../utilities/WPblogs.js"

const BlogPostTemplate = ({ data, location }) => {
  const { allContentfulBlog, contentfulBlog } = data

  const allPosts = [...allContentfulBlog.edges, ...WP.edges]

  const allSlugs = allPosts.map(({ node }) => {
    return node.slug
  })
  const currentWPContent = WPContent.edges
    .filter(({ node }) => `/blogi/${node.slug}` === location.pathname)
    .map(blog => blog.node)[0]

  const currentBlog = WP.edges
    .filter(({ node }) => `/blogi/${node.slug}` === location.pathname)
    .map(blog => blog.node)[0]
  const currentCat = currentBlog && currentBlog.categories.join(", ")

  const currentTags =
    currentBlog &&
    currentBlog.tags &&
    currentBlog.tags.map(tag => tag).join(", ")

  const createContentfulMarkup = () => {
    return { __html: contentfulBlog.body.childMarkdownRemark.html }
  }
  const createWPMarkup = () => {
    return { __html: currentWPContent.content }
  }

  const date = currentBlog
    ? formatDate(currentBlog.date)
    : formatDate(contentfulBlog.date)
  console.log(contentfulBlog.entryDescription.entryDescription)
  return (
    <Layout>
      {contentfulBlog && (
        <Helmet>
          <meta property="og:title" content={contentfulBlog.title} />

          <meta
            name="og:description"
            property="og:description"
            content={contentfulBlog.entryDescription.entryDescription}
          />
          <meta name="twitter:title" content={contentfulBlog.title} />
          <meta
            name="twitter:description"
            content={contentfulBlog.entryDescription.entryDescription}
          />
          <meta name="twitter:card" content="summary_large_image" />
          <meta
            name="twitter:image:src"
            content={`https:${contentfulBlog.entryImage.fluid.src}`}
          />
          <meta
            name="twitter:image"
            content={`https:${contentfulBlog.entryImage.fluid.src}`}
          />
        </Helmet>
      )}
      {currentBlog && (
        <Helmet>
          <meta property="og:title" content={currentBlog.title} />
          <meta
            name="og:image"
            property="og:image"
            content={selectImg(currentBlog.id)}
          />
          {/* <meta
                name="og:description"
                property="og:description"
                content={description}
              /> */}
          <meta name="twitter:title" content={currentBlog.title} />
          {/* <meta name="twitter:description" content={description} /> */}
          <meta name="twitter:card" content="summary_large_image" />
          <meta name="twitter:image:src" content={selectImg(currentBlog.id)} />
          <meta name="twitter:image" content={selectImg(currentBlog.id)} />
        </Helmet>
      )}

      <div style={{ paddingTop: "128px", backgroundColor: "#edf5f8" }}>
        <SEO title="blogi" />
        <Section isBlog>
          {contentfulBlog && (
            <BlogPost
              isFluid={!!contentfulBlog.entryImage}
              date={date}
              title={contentfulBlog.title}
              image={contentfulBlog.entryImage}
              tags={contentfulBlog.tags.join(", ")}
              categories={contentfulBlog.categories.join(", ")}
              slug={contentfulBlog.slug}
              allSlugs={allSlugs}
            >
              <div
                className="blog-post"
                dangerouslySetInnerHTML={createContentfulMarkup()}
              ></div>
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
              categories={currentCat}
              tags={currentTags}
              slug={currentBlog.slug}
              allSlugs={allSlugs}
            >
              <div
                className="blog-post"
                dangerouslySetInnerHTML={createWPMarkup()}
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
      categories
      slug
      entryDescription {
        entryDescription
      }
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
      body {
        id
        body
        childMarkdownRemark {
          html
        }
      }
    }

    allContentfulBlog: allContentfulBlogPost {
      edges {
        node {
          slug
        }
      }
    }
  }
`
