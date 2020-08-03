$(() => {
    const kysymykset = [
        "Pitääkö Lappilaisiakin voimakkaasti koskettava kaivostoiminta saattaa verolle?",
        "Eläkejärjestelmän, vanhustenhoidon turvaamiseksi ja valtiontalouden tasapainoon saattamiseksi pitää ennemmin korottaa veroja ja eläkemaksuja kuin suorittaa menoleikkauksia",
        "Pitääkö Suomessa lisätä maahanmuuttoa?",
        "Maanpuolustukselle on välttämätöntä hankkia 64 uutta hävittäjää.",
        "Pitääkö julkiset palvelut esimerkiksi terveydenhuolto ja viranomaispalvelut taata koko Lapin alueella."
];

const vastaukset = [
    [
        "Ei tarvitse, kaivostoiminta pitää olla veroton työllisyyden turvaamiseksi.",
        "Valtion pitää verottaa kaivostoimintaa samalla tavalla kuin kaikkia muitakin yrityksiä.",
        "Verotus pitää ohjata paikallisia tahoja hyödyttäväksi kunnalliseksi veroksi."
    ],
    [
        "Menoleikkauksia ja säästöjä pitää lisätä",
        "Veroja ja maksuja pitää korottaa",
        "Ei kumpaakaan näistä"
    ],
        [
        "Suomen pitää huolehtia humanitaarisesta maahanmuutosta sopimuksien mukaan.",
        "Maahanmuuttoa tulee lisätä tai pitää ennallaan.",
        "Suomi tarvitsee lisää työperäistä maahanmuuttoa."
    ],
        [
        "Uudet hävittäjät ovat riittävä pelote Venäjää vastaan. Hävittäjien hankinta on varmin tae Suomen sotilaalliselle     turvallisuudelle.",
        "Suomella on jo riittävä määrä Pariisin rauhansopimuksen mukaisia hävittäjiä.",
        "Suomen on ylläpidettävä riittävän suurta hävittäjälaivuetta ilmavalvonta ja puolustustehtäviin. Kaluston ylläpito ja käyttöiän pidentäminen on järkevämpi vaihtoehto maanpuolustuksellisesti."
    ],
        [
        "Palveluita voidaan keskittää isompiin kaupunkeihin.",
        "Palvelut tulee pitää kaikkien saatavilla ja lähellä.",
        "Tärkeimmät asiat voidaan hoitaa nykyään tietokoneella."
    ],
    
];

const vastineet = [
    [
        '2011 annetussa uudessa kaivoslaissa kaikki silloisessa "kansallissosialistisessa" hallituskoaliitiossa istuneet puolueet, sekä Keskusta joka valmisteli silloisen uuden  kaivoslain, vaativat kaivostoiminnan verottomaksi ja ajoivat kaivoslain verottomana toimintana suurille kaivosyhtiöille. Saamieni tietojen mukaan Vihreä liitto edellytti hyväksyntänsä edellytykseksi, että yksityisten pienten kaivostoimintaa harjoittavien kaivospiirit takavarikoidaan valtiolle ilman eri korvausta. Tämä vaatimus hyväksyttiin muiden toimesta ja kaivoslakiin kirjattiin kaivospiirien lakkautus.',
        "Kaivostoimintaa ei saa antaa valtion verotettavaksi. Valtio ei kuitenkaan ohjaa riittävästi saatuja verotuloja kaivospaikkakunnille vaan ohjaa verot Brysselin ja muiden maiden hyväksi.",
        "Valitsit oikean vaihtoehdon. Juuri näin pitää menetellä, niin kuin Seitsemän tähden liike vaatii!"
    ],
    [
        "Leikkaukset ja säästöt ei ole oikea ratkaisu. Valtion taloutta voidaan parantaa muilla keinoin. Katso alempaa enemmän näistä keinoista.",
        "Veron korotukset ei ole hyvä vaihtoehto. On olemassa parempia keinoja, lue niistä lisää ala puolelta.",
        "Olet oikeassa! Valtion taloutta voidaan parantaa muilla keinoin. Alapuolelta löydät näitä keinoja."
    ],
        [
        "Suomi on sitoutunut vastaanottamaan vuosittain 750 humanitäärisin perustein turvapaikkaa etsiviä.Suomen tulee noudattaa tämän kaltaisia tekemiään sopimuksia. Samaan aikaan on kuitenkin etsittävä keinoja miten turvapaikkaa hakevat saisivat turvallisen elinympäristön lähellä omaa kotimaataan. Kun Suomeen otetaan pakolaisia humanitäärisin perustein tulisi perusteet olla sellaiset että kulttuurillisesti Suomen kaltaisista väestöryhmistä tuleville annettaan etusija. Kulttuurillinen tausta on tärkein yksittäinen sopeutumiseen vaikuttava tekijä. Kulttuurien eriytyminen perustuu kykyyn säilyttää kulttuurillinen omaleimaisuus. Ne kulttuurit jotka ovat kyenneet oman identiteettinsä säilyttämään ja vahvistamaan ovat huonoja sopeutumaan muihin kulttuureihin. Valitsemalla tämän vaihtoehdon valitsit oikein ja samalla valitsit Seitsemän tähden liikkeen ajaman Suomelle hyvän linjan.",
        "Suomi ei tarvitse nähdyn kaltaista kontrolloimatonta maahanmuuttoa. Kuluneet vuodet ovat osoittaneet että Suomi ei kykene poliittisesti eikä taloudellisesti vastaanottamaan suuria ihmisjoukkoja. Oman maan kansalaiset, erityisesti vanhukset ja myös alhaisimman tulotason omaavat työelämässä olevat ja sosiialituen varaan turvautuvien ihmisten unohtaminen on johtanut ihmisten mielenilmaisuihin joiden johdosta heitä on perusteettomasti alettu syyttämään rasismista ja vihapuheesta. Nähtyjä terroritekoja, lapsiin kohdistuvista raiskauksia ja seksuaalisista hyväksikäyttöä vähätellään ja äänekkäästi mieltään ilmaisevat ihmiset tuomitaan raiskaajien tavoin.",
        "Suomella on liki puolen miljoonan työikäisen työvoimareservi odottamassa työllistymistä. Suomi ei tarvitse näin ollen lisää työperäistä maahanmuuttoa. Suomen pitää kyetä parantamaan työllisyyttä ja uudelleen kouluttamaan tarpeen mukaan työtä odottava työikäinen ja -kykyinen väestö. Sellaiset väittämät että työttömät eivät haluaisi takaisin työelämään, vaan odottamvat perustuloa tai muusta syystä katsovat paremmaksi pysytellä työelämän ulkouolella, ovat ihmisiä halventavia ja loukkaavia. Suomi on omaehtoisesti lähtenyt väärien talouspoliittisten päätösten myötä rapauttamaan omia työmarkkinoitaan. Liittymällä vastoin kansanlaisten tahtoa Euroalueeseen Suomi käytännössä antoi vientituotteidensa valmistus ja myyntihintojen määrittämisen isoille ostajamaille. Osallistuminen Venäjän vastaisiin pakotteisiin, joihin ei olisi pakkoliittymisvelvoitetta ollut, ja Venäjän asettamat vastapakotteet ovat olleet suomalaista vientikauppaa ja työllisyyttä heikentäviä, ja samaan aikaan suuret EU maat ovat lisänneet omaa vientiään ja työllisyyttä niillä aloilla joihin Venäjän vastapakotteet Suomessa kohdistuvat ja muualla eivät. Suomi ei tarvitse työperäistä maahanmuuttoa niin pitkään kuin oma väestö on samoja työmahdollisuuksia odottamassa."
    ],
        [
        "Kokemukset aikamme sodista osoittavat, ettei lentokoneilla pystytä torjumaan maitse tulevaa hyökkäystä. Onkohan meillä unohdettu, että Suomen maaraja mahdollista uhkaajaa vastaan on 1 300 kilometriä. Sen ylittäminen ei vaadi ilma-armeijaa, vaan käy parhaiten panssariyhtymien avulla. Jos hävittäjillä pystyttäisiin lyömään maavoimayksiköt, olisi USA peitonnut talibanit, liittokunta lyönyt isisin ja Turkki kukistanut kurdikapinalliset aikoja sitten. Näillä sotanäyttämöillä vahvemmalla osapuolella on sadoittain torjuntahävittäjiä. Voitot vain ovat antaneet odottaa itseään. Ensimmäiseksi pitäisi miettiä, millaiseen sotaan me joutuisimme yleiseurooppalaisessa kriisitilanteessa. Jos Venäjä toimisi samalla kaavalla, jota se on noudattanut viimeksi aloittamissaan sodissa, nousisivat maavoimat ja ohjusilmatorjunta hävittäjiä tärkeämmiksi. Hävittäjien ja korvettien hintalappu on pöyristyttävä. Sen rinnalla valtiovarainministeriön virkamiesten sopeutuspaketti on näpertelyä. Vielä pöyristyttävämmäksi asian tekee tieto, että vain kahden Super-Hornetin hinnalla Suomi pystyisi hankkimaan korkeakantamaiset ilmatorjuntaohjukset koko maan puolustamiseksi. Yhden hävittäjän hinnalla varustettaisiin kokonainen jääkäriprikaati. Valtiojohto leikittelee kansakunnan kohtalolla, kun se kopioi supervallan doktriinin pienen Suomen puolustusratkaisuksi.",
        "Suomelle on hankittu nykyiset Hornet hävittäjät vuosina 1995 – 2000. Niiden käyttöikä on alkujaan suunniteltu 30 vuodeksi. Ensiksi hankitut Hornet hävittäjät tulevat lasketun käyttöiän loppuun 2025. Osa Horneteista on myös tuhoutunut käytössä. Suomi tarvitsee uskottavan ilmavalvonta ja puolustustehtäviin kykenevän kaluston.",
        "Hävittäjähankinta on kallis investointi. Sen rahoittaminen uhkaa vaikeuttaa ohjuspuolustusjärjestelmän kehittämistä, maavoimien vahvistamista ja merivoimien suorituskyvyn kasvattamista. Nämä ovat ratkaisevassa asemassa oman maamme puolustamisessa. On syytä pohtia, löydämmekö edullisemman ratkaisun ilmavalvonnan ja -puolustuksen järjestämiseen. Tällainen voisi olla nykyisten koneiden elinkaaren jatkaminen. Voisimme harkita samankaltaista ratkaisua, johon Sveitsi on päätynyt. Sveitsillä on meneillään tarjouskilpailu, jossa sillä on samat hävittäjäehdokkaat kuin Suomella. Osana omaa hanketta siellä jatketaan nykyisten Hornet-hävittäjien elinkaarta. Samaan on päätynyt tiettävästi Kanada. Suomi voisi jatkaa nykyisten hävittäjien elinkaarta noin kymmenellä vuodella. Sveitsistä tulleiden tietojen perusteella tämä saattaisi maksaa noin miljardi euroa. Säästöjen avulla voisi tulla mahdolliseksi hankkia ulkomailta käytettyjä Hornet-hävittäjiä samaan tapaan kuin aikanaan tehtiin Hawk-koneiden suhteen. Tällöin koneiden kokonaismäärä voisi kasvaa tuntuvasti nykyistä suuremmaksi. Varoja jäisi käytettäväksi myös ohjuspuolustuksen investointeihin. Kun ilmavalvonta ja –puolustus saataisiin järjestetyksi edullisemmin, voisimme toteuttaa maavoimien ja merivoimien välttämättömät hankinnat ja lisätä kertausharjoituksia. Uusien koneiden hankinnan lykkääntyminen antaisi arvokasta aikaa tarjolla olevien vaihtoehtojen punnintaan. Tänä aikana teknologian ja koneiden kehitys saattaa muuttaa asetelmia."
    ],
        [
        "Palveluista osa voidaan ja joudutaan keskittämään isompiin kaupunkeihin. Jo nykyisin toimiva Lapin 15 kunnan omistama Lapin sairaanhoitopiirin kuntayhtymä ja 6 kunnan Länsi-Pohjan sairaanhoitopiiri vastaavat alueensa väestön erikoissairaanhoidosta sekä joukosta muita palveluja. Erikoissairaanhoito on esimerkki siitä mitä palveluja joudutaan ja kannattaa keskittää isompien asutustaajamien piiriin. Tiettyjen erityisalojen keskittäminen ei kuitenkaan saa johtaa muiden terveyspalvelujen keskittämistä erityisalojen mukana. Kunnille tulee antaa oikeus tuottaa terveydenhuollon palvelujen tuottaminen oman kantokyvyn mukaan ja yhteisten sopimusten kautta muiden kuntien kanssa yhdessä. Nykyisen palvelutason säilyminen kuntatasolla, erityisesti  terveydenhoidossa, on turvattava ja mieluummin parannettava palvelujen tuottamisen osalta kuin kaventamalla niitä. Peruspalvelut terveydenhuollon osalta on oltava  helposti saatavia ja ihmisläheisiä palveluja. Valtakunnan tasolla on käyty keskustelua pitäisikö Lapin sairaanhoitopiirit yhdistää tai osia palveluista siirtää vain  isomman hoidettavaksi. Päätökset siirrosta ei ole valtakunnan politiikkaa vaan alueen ihmisillä pitää olla erikoissairaanhoidon tuottamisesta päätäntävalta.",
            
        "Neuvola, lasten päivähoito ja lastensuojelu, terveyskeskus vuodeosastoineen ja päivystys pitää pystyä olla kaikkien kuntalaisten tavoitettavissa lähialueellaan. Pohjoisen Lapin osalta em. palvelujen tarjoaminen on haasteellinen ja tuottaa jatkossakin vaikeuksia. Alueen ihmiset ymmärtävät ja hyväksyvät pitkät etäisyydet, kunhan kuitenkin saavat asiallisen ja hyvän palvelun etäisyyksistä huolimatta. Hammashoito, Palvelutalot, TE-palvelut, Sosiaalitoimisto, peruskoulu tulee olla myös kuntalaisten saatavilla kohtuullisten etäisyyksien rajoissa. Ikääntyneiden asumis– ja liikkumispalveluiden kehittäminen kuuluu myös kunnallisiin helposti saataviin palveluihin. Kunnallinen terveyspalvelujen tarjonta pitää olla ensisijaisessa asemassa tulevassa sairaanhoidon ja terveyspalvelujen kehittämisessä. Sillä taataan kaikkien kuntalaisten hoitotarpeiden saatavuus varallisuudesta tai asuinpaikasta riippumatta. Yksityinen sektori voi toimia täydentävänä palveluna. Julkisen sektorin tuottamat terveyspalvelut ovat toimivia, Suomeakin paremmin, esimerkiksi Kanadassa. Julkisen sektorin kehittämiseen olisi syytä ottaa mallia sieltä missä se paremmin osataan.",
            
        "Lappilainen väestö hyväksyy ja on valmis käyttämään julkisen sektorin tuottamia digitaalisia palveluja laajasti kaikissa ikäryhmissä. Niiden kehittämistä pitää jatkaa. Edellytykset digitaalisille palveluille pitää kuitenkin saattaa toimintakuntoon. Internet- ja puhelinyhteydet eivät ole sillä tasolla mitä digitaalisten palveluiden täysimääräinen hyväksikäyttö edellyttäisi. Kun yhteydet ensin saadaan kuntoon ihmiset siirtyvät helpommin sähköisten palveluiden käyttäjiksi. Sähköisen ajanvarauksen laajentaminen terveydenhuollon palveluissa ja muiden viranomaispalvelujen laajentaminen ja käytön selkeyttäminen tarjoaa Lappilaisille pitkien etäisyyksien asukkaille hyvän rungon hyvään julkisen hallinnon palveluihin."
    ],

];
  
const kommentit = [
        "Kaivostoimintaa harjoittettavilla kunnilla pitää olla erityinen oikeus verottaa kaivostoimintaa oman verotuskäytäntönsä mukaan. Kunnat joiden alueilla kaivostoimintaa harjoitetaan joutuvat jo kaivostoiminnan suunnittelu vaiheessa varautumaan mahdollisen tulevan kaivostoiminnan vaatimaan infrastruktuurin rajuunkin lisäämiseen ja uudelleen rakentamisen. Iso kaivos pienellä paikkakunnalla lisää merkittävästi uusien päiväkotipaikkojen, koulupaikkkojen, asuntojen sekä muiden palvelujen rakentamisen ja saatavuuden turvaamisen. Kun kaivostoiminta loppuu edessä on alueen varsin äkillinen tyhjentyminen. Aikaisemmin tarpeelliset rakennukset ja palvelut muuttuvat ylimitoitetuksi tai jäävät kokonaan vaille käyttöä. Ison kaivostoiminnan loppuminen jättää aina myös isot jäljet toiminta-alueen luontoon. Vaikka luonnon ennalleen saattaminen onkin asetettu kaivostoiminnan harjoittajan vastuulle on kaikissa tapauksissa nähty että vastuut ovat kovin vähäiset vahinkoihin nähden. Kaivosalueiden ennallistamisen menettyleistä huolimatta hylätyt kaivosalueet jäävät aina paikallisille asukkaille perintöinä, pitkäksi aikaa käyttökelvottomana aikaisemmille elinkeino tai harrastetoiminnoille. Erityisesti poronhoito ja matkailu voivat olla suuria kärsijöitä. Näiden ennen ja jälkeen kaivostoimintaa tapahtuvien kustannuksien kattamiseksi kaivosten verotusoikeus pitää siirtää kunnille joilla kaivostoimintaa harjoitetaan. Kuntien verotus oikeus alentaa myös alueen ihmisten suhtautumista kaivostoimintaan myönteisemmäksi, kun tiedetään että kaivostoiminnasta on alueelle pitkällä aikavälillä tasaisesti tuottoa.",
  
        "Ainoa oikea tapa valtion talouden tasapainoon saamiseksi on työllisyyden parantaminen. Suomi on kuluneilla vaalikausilla ajanut omatahtoisesti kansantaloutta supistavaa näivettämis- ja miellyttämispolitiikkaa suurten EU maiden hyväksi. Suomen tulee kyetä palauttamaan oikeudet oman maan kansalaisten hyvinvoinnin rakentamiseen ja omaan kauppapolitiikkaan. Valtiontalouden tasapainottamiseksi, eläkejärjestelmän ja vanhustenhoidon turvaamiseksi valtion on huolehdittava työllisyydestä. Valtion verotuloja on lisättävä kitkemällä veronkierron mahdollisuuksia niin sanotulla verosuunnitteluilla jotka mahdollistavat laillisen veronkierron. Suomessa on n. 1/2 miljoonan työvoima reservi. Näiden ihmisten työllistäminen pitää olla ensimmäisenä toimenpidelistalla sen sijaan että tarjotaan leikkauksia, säästöjä ja verojen ja muiden maksujen korotuksia. Työttömien työllistämisellä on tuplavaikutus kansantalouteemme. Työttömyyden vähentäminen vähentää valtion menoja ja samalla lisää valtion tuloja. 2000-luvulla valtion taloutta on hoidettu erityisen kehnosti. Työpaikkoja on siirretty ulos maasta väärän talouspolitiikan harjoittamisella. Ihmisten yritystoimintoja on lakkautettu mielivaltaisesti ilman lainsäädännöllistä tai muuta perustetta. Kotimaisen uusiutuvan energian käytön rajoittamista on perusteltu ilmastopolitiikalla, tilalle on tuotettu ulkopuolelta uusiutumatonta energiaa. On liitytty erikoiseen, Suomelle hyvin vahingolliseen, pakotepolitiikkaan Venäjää vastaan jossa suomalaiset on jätetty kaupankäynnin ulkopuolelle ja samaan aikaan Euroopan maat toisaalla ovat lisänneet kaupankäyntiä Suomelle tärkeillä kaupanaloilla. Poliitikot perustelevat menetettyjä markkinoita Venäjän määräämillä vastapakotteilla. Venäjä rakentaa ja puolustaa omaa maataan omalla tavallaan. Suomen kuuluisi myös puolustaa ja rakentaa maataan omalla tavallaan."
];
    
    let i = 0;
    
    const vaalikone = () => {
        $("#kysymys").text(kysymykset[i]);
    
        $("#btn1").text(vastaukset[i][0]);
        $("#btn2").text(vastaukset[i][1]);
        $("#btn3").text(vastaukset[i][2]);
    
        $("#btn1").click(() => {
        $("#vastine").text(vastineet[i][0]);
        $(".leipateksti").text(kommentit[i]);
      });
        $("#btn2").click(() => {
        $("#vastine").text(vastineet[i][1]);
        $(".leipateksti").text(kommentit[i]);
      });
        $("#btn3").click(() => {
        $("#vastine").text(vastineet[i][2]);
        $(".leipateksti").text(kommentit[i]);
      });
    }
  
    $("#btnnext").click(() => {
        i++;
        if (i < 5) {
          $("#vastine").text("");
          $(".leipateksti").text("");
          vaalikone();
        } else {
          $("#vastine").text("");
          $("#vastine").append("<h4>Tule kysymään lisää kysymyksiä <a target='_blank' href='https://www.facebook.com/Ehdolla-eduskuntaan-Jukka-Sarre-255830302035621/'>Facebook-sivultani.</a></h4>");
        }
        if (i > 0) {
          $("#btnprev").removeClass('piilo');
        }
    });
    
    $("#startnappi").click(() => {
      $("#startnappi").addClass('piilo');
      $("#kone").removeClass('piilo');
      vaalikone();
    });
  
    
    
    $("#btnprev").click(() => {
      if (i > 0) {
        i = i - 1;
      }
      vaalikone();
    });
  
  
    
    
});