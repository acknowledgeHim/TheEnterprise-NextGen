import scrapy
from scrapy.contrib.linkextractors.sgml import SgmlLinkExtractor
from scrapy.contrib.spiders import CrawlSpider, Rule
from scrapy.item import Item, Field

class GrabURL(Item):
    url = Field()

class SpiderTarget(scrapy.Spider):
    def __init__(self, name, start_urls, allowed_domains, result_file):
        #name = "PLACEHOLDERname"
        #start_urls = ["PLACEHOLDERstart_urls"]
        #allowed_domains = ["PLACEHOLDERallowed_domains"]
        #result_file = "PLACEHOLDERresult_file"
        pass

    def parse(self, response):
        """ Parse pages as they are visited """
        hxs = scrapy.HtmlXPathSelector(response)
        urls = hxs.select("//a").extract()
        for sel in response.xpath('//a'):
            url_text = sel.xpath('text()').extract()
            url_link = sel.xpath('@href').extract()
            print("22 webcrapper_template url_link: " + str(url_link))

        # Find dynamic vars (GET / POST)

        # Find file upload

        # Find login pages

        # Find emails

        # Find Vendors (Company Names)

        # Find Event Dates

        # Find javascript hosted on remote/3rd party site

        # Find links
        rules = (Rule(SgmlLinkExtractor(), callback='parse_url', follow=True),)

    def parse_url(self, response):
        item = GrabURL()
        item['url'] = response.url
        return itemf

    def parseCategory(self, response):
        '''Parse category page and extract links of the items.'''
        hxs = HtmlXPathSelector(response)
        links = hxs.select("//*[@id='_list']//td[@class='tListDesc']/a/@href").extract()
        for link in links:
            itemLink = urlparse.urljoin(response.url, link)
            self.log('Found item link: %s' % itemLink, log.DEBUG)
            yield Request(itemLink, callback=self.parseItem)
