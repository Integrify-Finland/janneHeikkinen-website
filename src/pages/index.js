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
      [BLOCKS.UL_LIST]: (node, children) => <ULlists>{children}</ULlists>,
    },
  }

  const renderBlogPost = () => {
    return documentToReactComponents(
      blogPost.childContentfulBlogPostContentRichTextNode.json,
      options
    )
  }

  // console.log(blogPost.)
  return (
    <Layout>
      <SEO title="Home" />
      <h1>{aboutMe.title}</h1>
      <p>{aboutMe.description}</p>
      <div style={{ maxWidth: `300px`, marginTop: `10rem` }}>
        <Image />
      </div>
      <h1>{blogPost.title}</h1>
      <span>Tags are: </span>
      {blogPost.tags.split(",").map(tag => (
        <>
          <span style={{ backgroundColor: "#bada55", marginLeft: "1rem" }}>
            {tag}{" "}
          </span>
        </>
      ))}
      {renderBlogPost()}
    </Layout>
  )
}

export default IndexPage

export const query = graphql`
  query {
    aboutMe: contentfulAboutMe {
      kotiPaikka
      syntynyt
      perhe
      sotilasarvo
      ammatti
      harrastukset
      koulutus
      luottamustehtava
    }
    blogPost: contentfulBlogPost {
      title
      tags
      childContentfulBlogPostContentRichTextNode {
        json
      }
    }
    contactUs: allContentfulContactUs {
      edges {
        node {
          name
          title
          phoneNumber
          email
        }
      }
    }
    DetailsAboutMe: allContentfulDetailsAboutMe {
      edges {
        node {
          title
          description {
            description
          }
        }
      }
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
  }
`
